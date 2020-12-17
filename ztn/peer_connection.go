package ztn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
)

type PeerConnection struct {
	myID        string
	peerID      string
	MyProfile   Profile
	PeerProfile PeerProfile

	launchedAt time.Time

	device *device.Device
	logger *device.Logger

	started       bool
	lastKeepalive time.Time

	lastRX uint64
	lastTX uint64

	lastInboundPacket time.Time
	connectedInbound  bool

	lastOutboundPacket time.Time
	connectedOutbound  bool

	connectedOnce bool

	offersBridging bool

	try int

	bothStunning bool
	stunPeerConn *net.UDPConn

	Status         string
	ConnectionType string

	networkConnection *NetworkConnection
}

func NewPeerConnection(d *device.Device, logger *device.Logger, myProfile Profile, peerProfile PeerProfile, networkConnection *NetworkConnection) *PeerConnection {
	pc := &PeerConnection{
		device:            d,
		logger:            logger.AddPrepend(fmt.Sprintf("(PEER:%s) ", peerProfile.Hostname)),
		myID:              myProfile.PublicKey,
		peerID:            peerProfile.PublicKey,
		MyProfile:         myProfile,
		PeerProfile:       peerProfile,
		networkConnection: networkConnection,
		launchedAt:        time.Now(),
	}
	return pc
}

func (pc *PeerConnection) Start() {
	pc.Status = PEER_STATUS_INITIATING_CONNECTION

	for {
		pc.run()
		pc.reset()
		pc.logger.Error.Println("Lost connection with", pc.peerID, ". Reconnecting")
	}
}

func (pc *PeerConnection) reset() {
	pc.started = false
	pc.lastKeepalive = time.Time{}

	pc.connectedInbound = false
	pc.lastInboundPacket = time.Time{}
	pc.connectedOutbound = false
	pc.lastOutboundPacket = time.Time{}

	// If we were connected once, then our previous try ID was a good one
	if pc.connectedOnce {
		pc.try = pc.try - 1
	}

	pc.connectedOnce = false

	pc.offersBridging = false

	if pc.stunPeerConn != nil {
		pc.stunPeerConn.Close()
	}

	pc.Status = PEER_STATUS_INITIATING_CONNECTION

	pc.RemovePeer()
}

func (pc *PeerConnection) run() {
	var peerAddrChan chan *NetworkEndpointEvent

	keepalive := time.Tick(500 * time.Millisecond)

	foundPeer := make(chan bool)

	var peerAddr *net.UDPAddr

	for {
		res := func() bool {
			select {
			case nee := <-peerAddrChan:

				if nee == nil {
					pc.logger.Info.Println("No connection could be established to", pc.peerID)
					peerAddrChan = nil
					return true
				}

				pc.HandleNetworkEndpointEvent(nee)

				pc.ConnectionType = pc.FindConnectionType(nee)
				var peerStr string
				if pc.ConnectionType == ConnectionTypeLANIN || pc.ConnectionType == ConnectionTypeLANOUT {
					pc.Status = PEER_STATUS_CONNECT_PRIVATE
					peerStr = nee.PrivateEndpoint
				} else {
					pc.Status = PEER_STATUS_CONNECT_PUBLIC
					peerStr = nee.PublicEndpoint
				}

				var err error
				peerAddr, err = net.ResolveUDPAddr(udp, peerStr)
				sharedutils.CheckError(err)

				pc.logger.Debug.Println("Publishing for peer join", pc.peerID)
				GLPPublish(pc.PublishP2PKey(), pc.buildNetworkEndpointEvent())

				pc.setupPeerConnection(peerStr, peerAddr)

				pc.started = true
				pc.try++
				// If we're ever going to go to max int and get into negative numbers, we reset to 0 since -1 has a special meaning
				if pc.try < 0 {
					pc.logger.Info.Println("We have a negative try ID, reseting it to 0")
					pc.try = 0
				}
				pc.lastKeepalive = time.Now()
				foundPeer <- true

			case <-keepalive:
				if !pc.CheckConnectionLiveness() {
					return false
				}

				if peerAddr != nil {
					udpSendStr(pingMsg, pc.networkConnection.localConn, peerAddr)
				}

				if pc.networkConnection.publicAddr != nil && peerAddrChan == nil {
					pc.logger.Info.Println("Got a public IP address", pc.networkConnection.publicAddr, "for peer", pc.peerID, ". Obtained via", pc.networkConnection.BindTechnique)
					peerAddrChan = pc.StartConnection(foundPeer)
				}

				if pc.Connected() {
					// Decrement try so that next time its used it will use the same technique that just worked
					pc.connectedOnce = true
					pc.Status = fmt.Sprintf("%s (%s)", PEER_STATUS_CONNECTED, pc.ConnectionType)
				} else if pc.started && time.Since(pc.lastKeepalive) > pc.ConnectionLivenessTolerance() {
					pc.logger.Error.Println("No packet or keepalive received for too long. Connection to", pc.peerID, "is dead")
					return false
				}
			}
			return true
		}()
		if !res {
			return
		}
	}
}

func (pc *PeerConnection) listen(conn *net.UDPConn, messages chan *pkt) {
	go func() {
		for {
			buf := defaultBufferPool.Get()

			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				close(messages)
				return
			}
			buf = buf[:n]

			messages <- &pkt{raddr: raddr, message: buf}
		}
	}()
}

func (pc *PeerConnection) PublishP2PKey() string {
	return pc.buildP2PKey(pc.MyProfile.PublicKey, pc.PeerProfile.PublicKey)
}

func (pc *PeerConnection) ListenP2PKey() string {
	return pc.buildP2PKey(pc.PeerProfile.PublicKey, pc.MyProfile.PublicKey)
}

func (pc *PeerConnection) buildP2PKey(key1, key2 string) string {
	key1dec, err := base64.StdEncoding.DecodeString(key1)
	sharedutils.CheckError(err)
	key2dec, err := base64.StdEncoding.DecodeString(key2)
	sharedutils.CheckError(err)

	combined := append(key1dec, key2dec...)
	return base64.URLEncoding.EncodeToString(combined)
}

func (pc *PeerConnection) getPrivateAddr() string {
	conn, err := net.Dial("udp", stunServer)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return fmt.Sprintf("%s:%d", localAddr.IP.String(), localWGPort)
}

type NetworkEndpointEvent struct {
	ID              string        `json:"id"`
	PublicEndpoint  string        `json:"public_endpoint"`
	PrivateEndpoint string        `json:"private_endpoint"`
	Try             int           `json:"try"`
	BindTechnique   BindTechnique `json:"bind_technique"`
	OffersBridging  bool          `json:"offers_bridging"`
	SentOn          time.Time     `json:"sent_on"`
	LaunchedAt      time.Time     `json:"launched_at"`
}

func (nee NetworkEndpointEvent) ToJSON() []byte {
	b, err := json.Marshal(nee)
	sharedutils.CheckError(err)
	return b
}

func (pc *PeerConnection) buildNetworkEndpointEvent() Event {
	return Event{Type: "network_endpoint", Data: NetworkEndpointEvent{
		ID:              pc.MyProfile.PublicKey,
		PublicEndpoint:  pc.networkConnection.publicAddr.String(),
		PrivateEndpoint: pc.getPrivateAddr(),
		Try:             pc.try,
		BindTechnique:   pc.networkConnection.BindTechnique,
		OffersBridging:  sharedutils.EnvOrDefault(EnvOffersBridging, "false") == "true",
		SentOn:          time.Now(),
		LaunchedAt:      pc.launchedAt,
	}.ToJSON()}
}

func (pc *PeerConnection) getPeerAddr() chan *NetworkEndpointEvent {
	result := make(chan *NetworkEndpointEvent)
	myID := pc.MyProfile.PublicKey

	p2pk := pc.ListenP2PKey()

	go func() {
		c := GLPClient(p2pk)
		c.Start(APIClientCtx)
		defer c.Stop()
		maxWait := time.After(PublicPortLivenessTolerance)
		for {
			select {
			case <-maxWait:
				result <- nil
				return
			case e := <-c.EventsChan:
				event := Event{}
				err := json.Unmarshal(e.Data, &event)
				sharedutils.CheckError(err)
				if event.Type == "network_endpoint" {
					nee := NetworkEndpointEvent{}
					err = json.Unmarshal(event.Data, &nee)
					sharedutils.CheckError(err)
					if nee.ID != myID {
						result <- &nee
						return
					}
				}
			}
		}
	}()

	return result
}

func (pc *PeerConnection) IAmTheBestTryHolder(nee *NetworkEndpointEvent) bool {
	return pc.launchedAt.Before(nee.LaunchedAt)
}

func (pc *PeerConnection) HandleNetworkEndpointEvent(nee *NetworkEndpointEvent) {
	pc.logger.Info.Printf("Received network endpoint event dated from %s. Remote info: (launched at:%s) (bind technique:%s) (can offer bridging:%t) (public endpoint:%s) (private endpoint %s) (try ID %d)", nee.LaunchedAt, nee.SentOn, nee.BindTechnique, nee.OffersBridging, nee.PublicEndpoint, nee.PrivateEndpoint, nee.Try)

	if pc.IAmTheBestTryHolder(nee) {
		pc.logger.Info.Println("Using my own try")
		// I know this is pretty useless but I just wanted to make it explicit
		pc.try = pc.try
	} else {
		pc.logger.Info.Println("Using try from peer")
		pc.try = nee.Try
	}
	pc.logger.Info.Println("Using try ID", pc.try)

	if nee.BindTechnique == BindSTUN && pc.networkConnection.BindTechnique == BindSTUN {
		pc.logger.Debug.Println("Self and peer are using STUN to connect")
		pc.bothStunning = true
	} else {
		pc.logger.Debug.Println("Either self or peer isn't using STUN to connect")
		pc.bothStunning = false
	}
	pc.offersBridging = nee.OffersBridging
}

func (pc *PeerConnection) IAmTheSmallestKey() bool {
	return pc.MyProfile.PublicKey < pc.PeerProfile.PublicKey
}

func (pc *PeerConnection) Connected() bool {
	return pc.connectedInbound && pc.connectedOutbound
}

func (pc *PeerConnection) StartConnection(foundPeer chan bool) chan *NetworkEndpointEvent {
	go func() {
		GLPPublish(pc.PublishP2PKey(), pc.buildNetworkEndpointEvent())
		after := []time.Duration{
			5 * time.Second,
		}
		i := 0
		for {
			select {
			case <-time.After(after[i%len(after)]):
				i++
				pc.logger.Debug.Println("Publishing IP for discovery with peer", pc.peerID)
				GLPPublish(pc.PublishP2PKey(), pc.buildNetworkEndpointEvent())
			case <-foundPeer:
				pc.logger.Info.Println("Found peer", pc.peerID, ", stopping the publishing")
				return
			}
		}
	}()

	return pc.getPeerAddr()
}

func (pc *PeerConnection) setupPeerConnection(peerStr string, peerAddr *net.UDPAddr) {
	conf := ""

	conf += fmt.Sprintf("public_key=%s\n", keyToHex(pc.PeerProfile.PublicKey))
	switch pc.ConnectionType {
	case ConnectionTypeLANOUT:
		conf += fmt.Sprintf("endpoint=%s\n", peerStr)
	case ConnectionTypeLANIN:
		//Nothing to do
	case ConnectionTypeWANSTUN:
		go func() {
			pc.networkConnection.RecordInboundAttempt()
		}()
		var err error
		pc.stunPeerConn, err = net.ListenUDP(udp, nil)
		sharedutils.CheckError(err)
		pc.networkConnection.listen(pc.stunPeerConn, pc.networkConnection.messageChan)
		pc.networkConnection.peerConnections[pc.stunPeerConn.LocalAddr().String()] = &bridge{conn: pc.networkConnection.localConn, raddr: peerAddr}
		a := strings.Split(pc.stunPeerConn.LocalAddr().String(), ":")
		conf += fmt.Sprintf("endpoint=%s\n", fmt.Sprintf("127.0.0.1:%s", a[len(a)-1]))
	case ConnectionTypeWANOUT:
		conf += fmt.Sprintf("endpoint=%s\n", peerStr)
	case ConnectionTypeWANIN:
		go func() {
			pc.networkConnection.RecordInboundAttempt()
		}()
	default:
		panic("Unknown connection type")
	}

	conf += "replace_allowed_ips=true\n"
	if pc.PeerProfile.IsGateway {
		conf += "allowed_ip=0.0.0.0/0\n"
	} else {
		conf += fmt.Sprintf("allowed_ip=%s/32\n", pc.PeerProfile.WireguardIP.String())
	}
	conf += "persistent_keepalive_interval=1"

	pc.Status += fmt.Sprintf(" (%s)", pc.ConnectionType)

	pc.logger.Info.Println(pc.Status)

	SetConfigMulti(pc.device, conf)

}

func (pc *PeerConnection) RemovePeer() {
	conf := ""
	conf += fmt.Sprintf("public_key=%s\n", keyToHex(pc.PeerProfile.PublicKey))
	conf += "remove=true\n"
	SetConfigMulti(pc.device, conf)
}

func (pc *PeerConnection) CheckConnectionLiveness() bool {
	result := true
	pc.device.WithPeers(func(peers map[device.NoisePublicKey]*device.Peer) {
		for _, peer := range peers {
			if pc.peerID == peer.GetPublicKey() {
				stats := peer.GetStats()
				if stats.TX != pc.lastTX {
					pc.connectedOutbound = true
					pc.lastOutboundPacket = time.Now()
					pc.lastTX = stats.TX
				} else if time.Since(pc.lastOutboundPacket) > pc.ConnectionLivenessTolerance() {
					if pc.connectedOutbound {
						pc.logger.Error.Println("Outbound connection lost to", pc.peerID)
						result = false
					}
					pc.connectedOutbound = false
				}

				if stats.RX != pc.lastRX {
					pc.connectedInbound = true
					pc.lastInboundPacket = time.Now()
					pc.lastRX = stats.RX
				} else if time.Since(pc.lastInboundPacket) > pc.ConnectionLivenessTolerance() {
					if pc.connectedInbound {
						pc.logger.Error.Println("Inbound connection lost to", pc.peerID)
						result = false
					}
					pc.connectedInbound = false
				}
			}
		}
	})
	return result
}

func (pc *PeerConnection) OffersBridging() bool {
	return pc.offersBridging
}

func (pc *PeerConnection) ConnectionLivenessTolerance() time.Duration {
	if pc.connectedOnce {
		return ConnectedConnectionLivenessTolerance
	} else {
		return InitialConnectionLivenessTolerance
	}
}

func (pc *PeerConnection) IAmTheBestWANIN(nee *NetworkEndpointEvent) bool {
	pc.logger.Info.Println(pc.networkConnection.BindTechnique, "my weight", pc.networkConnection.BindTechnique.Weight(), "other weight", nee.BindTechnique.Weight())
	if pc.networkConnection.BindTechnique.Weight() == nee.BindTechnique.Weight() {
		return !pc.IAmTheSmallestKey()
	} else {
		return pc.networkConnection.BindTechnique.Weight() > nee.BindTechnique.Weight()
	}
}

func (pc *PeerConnection) FindConnectionType(nee *NetworkEndpointEvent) string {
	tryMod := pc.try % 6

	switch tryMod {
	case 0:
		return pc.connectionTypeWan1(nee)
	case 1:
		return pc.connectionTypeLan1(nee)
	case 2:
		return pc.connectionTypeWan2(nee)
	case 3:
		return pc.connectionTypeLan2(nee)
	case 4:
		return pc.connectionTypeWan1(nee)
	case 5:
		return pc.connectionTypeWan2(nee)
	default:
		panic("Unknown modulo when trying to find connection type")
	}
}

func (pc *PeerConnection) connectionTypeLan1(nee *NetworkEndpointEvent) string {
	if pc.IAmTheSmallestKey() {
		return ConnectionTypeLANIN
	} else {
		return ConnectionTypeLANOUT
	}
}

func (pc *PeerConnection) connectionTypeLan2(nee *NetworkEndpointEvent) string {
	if pc.IAmTheSmallestKey() {
		return ConnectionTypeLANOUT
	} else {
		return ConnectionTypeLANIN
	}
}

func (pc *PeerConnection) connectionTypeWan1(nee *NetworkEndpointEvent) string {
	if pc.bothStunning {
		return ConnectionTypeWANSTUN
	} else if pc.IAmTheBestWANIN(nee) {
		return ConnectionTypeWANIN
	} else {
		return ConnectionTypeWANOUT
	}
}

func (pc *PeerConnection) connectionTypeWan2(nee *NetworkEndpointEvent) string {
	if pc.bothStunning {
		return ConnectionTypeWANSTUN
	} else if pc.IAmTheBestWANIN(nee) {
		return ConnectionTypeWANOUT
	} else {
		return ConnectionTypeWANIN
	}
}
