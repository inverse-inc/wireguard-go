package ztn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
)

type BindTechnique string

type PeerConnection struct {
	myID        string
	peerID      string
	MyProfile   Profile
	PeerProfile PeerProfile

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

	try int

	bothStunning bool
	stunPeerConn *net.UDPConn

	Status string

	BindTechnique BindTechnique

	networkConnection *NetworkConnection
}

func NewPeerConnection(d *device.Device, logger *device.Logger, myProfile Profile, peerProfile PeerProfile, networkConnection *NetworkConnection) *PeerConnection {
	pc := &PeerConnection{
		device:            d,
		logger:            logger,
		myID:              myProfile.PublicKey,
		peerID:            peerProfile.PublicKey,
		MyProfile:         myProfile,
		PeerProfile:       peerProfile,
		BindTechnique:     DefaultBindTechnique,
		networkConnection: networkConnection,
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

	// Reset the try flag if a connection attempt was already successful so that it retries from scratch next time
	if pc.Connected() {
		pc.try = 0
	}
	pc.connectedInbound = false
	pc.lastInboundPacket = time.Time{}
	pc.connectedOutbound = false
	pc.lastOutboundPacket = time.Time{}

	if pc.stunPeerConn != nil {
		pc.stunPeerConn.Close()
	}

	pc.Status = PEER_STATUS_INITIATING_CONNECTION
}

func (pc *PeerConnection) run() {
	var peerAddrChan chan string

	keepalive := time.Tick(500 * time.Millisecond)

	foundPeer := make(chan bool)

	var peerAddr *net.UDPAddr

	for {
		res := func() bool {
			select {
			case peerStr := <-peerAddrChan:
				if pc.ShouldTryPrivate() {
					pc.logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", pc.peerID, ". This connection attempt may fail")
					pc.Status = PEER_STATUS_CONNECT_PRIVATE
				} else {
					pc.logger.Info.Println("Connecting to public IP address of peer", peerStr, "for peer", pc.peerID, ".")
					pc.Status = PEER_STATUS_CONNECT_PUBLIC
				}

				var err error
				peerAddr, err = net.ResolveUDPAddr(udp, peerStr)
				sharedutils.CheckError(err)

				pc.logger.Debug.Println("Publishing for peer join", pc.peerID)
				GLPPublish(pc.buildP2PKey(), pc.buildNetworkEndpointEvent())

				pc.setupPeerConnection(peerStr, peerAddr)

				pc.started = true
				pc.try++
				foundPeer <- true
				pc.lastKeepalive = time.Now()

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
					pc.Status = PEER_STATUS_CONNECTED
				} else if pc.started && time.Since(pc.lastKeepalive) > ConnectionLivenessTolerance {
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

func (pc *PeerConnection) buildP2PKey() string {
	key1 := pc.MyProfile.PublicKey
	key2 := pc.PeerProfile.PublicKey
	if key2 < key1 {
		key1bak := key1
		key1 = key2
		key2 = key1bak
	}

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

func (pc *PeerConnection) buildNetworkEndpointEvent() Event {
	return Event{Type: "network_endpoint", Data: gin.H{
		"id":               pc.MyProfile.PublicKey,
		"public_endpoint":  pc.networkConnection.publicAddr.String(),
		"private_endpoint": pc.getPrivateAddr(),
		"try":              pc.try,
		"bind_technique":   pc.networkConnection.BindTechnique,
	}}
}

func (pc *PeerConnection) getPeerAddr() chan string {
	result := make(chan string)
	myID := pc.MyProfile.PublicKey

	p2pk := pc.buildP2PKey()

	go func() {
		c := GLPClient(p2pk)
		c.Start(APIClientCtx)
		for {
			select {
			case e := <-c.EventsChan:
				event := Event{}
				err := json.Unmarshal(e.Data, &event)
				sharedutils.CheckError(err)
				if event.Type == "network_endpoint" && event.Data["id"].(string) != myID {
					// Follow what the peer says if he has a bigger key
					if event.Data["try"] != nil && pc.IAmTheSmallestKey() {
						pc.try = int(event.Data["try"].(float64))
						pc.logger.Info.Println("Using peer defined try ID", pc.try)
					}
					if event.Data["bind_technique"].(string) == string(BindSTUN) && pc.networkConnection.BindTechnique == BindSTUN {
						pc.logger.Debug.Println("Self and peer are using STUN to connect")
						pc.bothStunning = true
					} else {
						pc.logger.Debug.Println("Either self or peer isn't using STUN to connect")
						pc.bothStunning = false
					}
					if pc.ShouldTryPrivate() {
						result <- event.Data["private_endpoint"].(string)
						return
					} else {
						result <- event.Data["public_endpoint"].(string)
						return
					}
				}
			}
		}
	}()

	return result
}

func (pc *PeerConnection) IAmTheSmallestKey() bool {
	return pc.MyProfile.PublicKey < pc.PeerProfile.PublicKey
}

func (pc *PeerConnection) ShouldTryPrivate() bool {
	return pc.try%3 == 0
}

func (pc *PeerConnection) MyTurnPublicConnect() bool {
	if pc.IAmTheSmallestKey() && pc.try%3 == 1 {
		return true
	} else if !pc.IAmTheSmallestKey() && pc.try%3 == 2 {
		return true
	} else {
		return false
	}
}

func (pc *PeerConnection) Connected() bool {
	return pc.connectedInbound && pc.connectedOutbound
}

func (pc *PeerConnection) StartConnection(foundPeer chan bool) chan string {
	go func() {
		for {
			select {
			case <-time.After(1 * time.Second):
				pc.logger.Debug.Println("Publishing IP for discovery with peer", pc.peerID)
				GLPPublish(pc.buildP2PKey(), pc.buildNetworkEndpointEvent())
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
	if pc.ShouldTryPrivate() {
		conf += fmt.Sprintf("endpoint=%s\n", peerStr)
	} else if pc.bothStunning {
		var err error
		pc.stunPeerConn, err = net.ListenUDP(udp, nil)
		sharedutils.CheckError(err)
		pc.networkConnection.listen(pc.stunPeerConn, pc.networkConnection.messageChan)
		pc.networkConnection.peerConnections[pc.stunPeerConn.LocalAddr().String()] = &bridge{conn: pc.networkConnection.localConn, raddr: peerAddr}
		a := strings.Split(pc.stunPeerConn.LocalAddr().String(), ":")
		conf += fmt.Sprintf("endpoint=%s\n", fmt.Sprintf("127.0.0.1:%s", a[len(a)-1]))
	} else if pc.MyTurnPublicConnect() {
		conf += fmt.Sprintf("endpoint=%s\n", peerStr)
	}
	conf += "replace_allowed_ips=true\n"
	if pc.PeerProfile.IsGateway {
		conf += "allowed_ip=0.0.0.0/0\n"
	} else {
		conf += fmt.Sprintf("allowed_ip=%s/32\n", pc.PeerProfile.WireguardIP.String())
	}
	conf += "persistent_keepalive_interval=1"

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
				} else if time.Since(pc.lastOutboundPacket) > ConnectionLivenessTolerance {
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
				} else if time.Since(pc.lastInboundPacket) > ConnectionLivenessTolerance {
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
