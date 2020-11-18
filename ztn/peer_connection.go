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

const udp = "udp"
const pingMsg = "ping"

const stunServer = "srv.semaan.ca:3478"

const connectionLivenessTolerance = 10 * time.Second

type BindTechnique string

const (
	BindSTUN    = BindTechnique("STUN")
	BindUPNPGID = BindTechnique("UPNPGID")
	BindNATPMP  = BindTechnique("NATPMP")
)

var DefaultBindTechnique = BindSTUN

type pkt struct {
	conn    *net.UDPConn
	raddr   *net.UDPAddr
	message []byte
}

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

	pc.Status = PEER_STATUS_INITIATING_CONNECTION
}

func (pc *PeerConnection) run() {
	var peerAddrChan chan string

	keepalive := time.Tick(500 * time.Millisecond)

	foundPeer := make(chan bool)

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

				pc.logger.Debug.Println("Publishing for peer join", pc.peerID)
				GLPPublish(pc.buildP2PKey(), pc.buildNetworkEndpointEvent())

				pc.setupPeerConnection(peerStr)

				pc.started = true
				pc.try++
				foundPeer <- true
				pc.lastKeepalive = time.Now()

			case <-keepalive:
				if !pc.CheckConnectionLiveness() {
					return false
				}

				if pc.networkConnection.publicAddr != nil && peerAddrChan == nil {
					pc.logger.Info.Println("Got a public IP address", pc.networkConnection.publicAddr, "for peer", pc.peerID)
					peerAddrChan = pc.StartConnection(foundPeer)
				}

				if pc.Connected() {
					pc.Status = PEER_STATUS_CONNECTED
				} else if pc.started && pc.lastKeepalive.Before(time.Now().Add(-5*time.Second)) {
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

	a := strings.Split(pc.networkConnection.publicAddr.String(), ":")
	return localAddr.IP.String() + ":" + a[len(a)-1]
}

func (pc *PeerConnection) buildNetworkEndpointEvent() Event {
	return Event{Type: "network_endpoint", Data: gin.H{
		"id":               pc.MyProfile.PublicKey,
		"public_endpoint":  pc.networkConnection.publicAddr.String(),
		"private_endpoint": pc.getPrivateAddr(),
		"try":              pc.try,
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
					if event.Data["try"] != nil && pc.MyProfile.PublicKey < pc.PeerProfile.PublicKey {
						pc.try = int(event.Data["try"].(float64))
						pc.logger.Info.Println("Using peer defined try ID", pc.try)
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

func (pc *PeerConnection) ShouldTryPrivate() bool {
	return pc.try%2 == 0
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

func (pc *PeerConnection) setupPeerConnection(peerStr string) {
	conf := ""
	conf += fmt.Sprintf("public_key=%s\n", keyToHex(pc.PeerProfile.PublicKey))
	conf += fmt.Sprintf("endpoint=%s\n", peerStr)
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
				} else if time.Since(pc.lastOutboundPacket) > connectionLivenessTolerance {
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
				} else if time.Since(pc.lastInboundPacket) > connectionLivenessTolerance {
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
