package ztn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"gortc.io/stun"
)

const udp = "udp"
const pingMsg = "ping"

const stunServer = "srv.semaan.ca:3478"

type BindTechnique string

const (
	BindSTUN    = BindTechnique("STUN")
	BindUPNPGID = BindTechnique("UPNPGID")
)

var DefaultBindTechnique = BindSTUN

type pkt struct {
	raddr   *net.UDPAddr
	message []byte
}

type PeerConnection struct {
	myID        string
	peerID      string
	MyProfile   Profile
	PeerProfile PeerProfile

	wgConn        *net.UDPConn
	localPeerConn *net.UDPConn
	device        *device.Device
	logger        *device.Logger

	myAddr   *net.UDPAddr
	peerAddr *net.UDPAddr

	started       bool
	lastKeepalive time.Time

	connectedInbound  bool
	connectedOutbound bool

	triedPrivate bool

	BindTechnique BindTechnique
}

func NewPeerConnection(d *device.Device, logger *device.Logger, myProfile Profile, peerProfile PeerProfile) *PeerConnection {
	pc := &PeerConnection{
		device:        d,
		logger:        logger,
		myID:          myProfile.PublicKey,
		peerID:        peerProfile.PublicKey,
		MyProfile:     myProfile,
		PeerProfile:   peerProfile,
		BindTechnique: DefaultBindTechnique,
	}
	return pc
}

func (pc *PeerConnection) Start() {
	for {
		pc.run()
		pc.reset()
		pc.logger.Error.Println("Lost connection with", pc.peerID, ". Reconnecting")
	}
}

func (pc *PeerConnection) reset() {
	pc.wgConn = nil
	pc.localPeerConn = nil
	pc.myAddr = nil
	pc.peerAddr = nil
	pc.started = false
	pc.lastKeepalive = time.Time{}

	// Reset the triedPrivate flag if a connection attempt was already successful so that it retries from scratch next time
	if pc.Connected() {
		pc.triedPrivate = false
	}
	pc.connectedInbound = false
	pc.connectedOutbound = false
}

func (pc *PeerConnection) run() {
	var err error
	pc.wgConn, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: localWGIP, Port: localWGPort})
	sharedutils.CheckError(err)

	stunAddr, err := net.ResolveUDPAddr(udp, stunServer)
	sharedutils.CheckError(err)

	pc.localPeerConn, err = net.ListenUDP(udp, nil)
	sharedutils.CheckError(err)

	pc.logger.Debug.Printf("Listening on %s for peer %s\n", pc.localPeerConn.LocalAddr(), pc.peerID)

	var stunPublicAddr stun.XORMappedAddress

	peerupnpgid := NewUPNPGID()

	messageChan := make(chan *pkt)
	pc.listen(pc.localPeerConn, messageChan)
	pc.listen(pc.wgConn, messageChan)
	var peerAddrChan <-chan string

	keepalive := time.Tick(500 * time.Millisecond)
	keepaliveMsg := pingMsg

	foundPeer := make(chan bool)

	a := strings.Split(pc.localPeerConn.LocalAddr().String(), ":")
	localPeerPort, err := strconv.Atoi(a[len(a)-1])
	sharedutils.CheckError(err)
	var localPeerAddr = fmt.Sprintf("%s:%d", localWGIP.String(), localPeerPort)
	var localWGAddr = fmt.Sprintf("%s:%d", localWGIP.String(), localWGPort)

	for {
		res := func() bool {
			var message *pkt
			var ok bool

			defer func() {
				if message != nil {
					defaultBufferPool.Put(message.message)
				}
			}()

			select {
			case message, ok = <-messageChan:
				if !ok {
					return false
				}

				switch {
				case peerupnpgid.IsMessage(message.message):
					externalIP, externalPort, err := peerupnpgid.ParseBindRequestPkt(message.message)
					if err != nil {
						pc.logger.Error.Println("Unable to decode UPNP GID message:", err)
						break
					}

					newaddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", externalIP, externalPort))
					sharedutils.CheckError(err)
					if newaddr.String() != pc.myAddr.String() {
						pc.myAddr = newaddr
						peerAddrChan = pc.StartConnection(foundPeer)
					}

				case stun.IsMessage(message.message):
					m := new(stun.Message)
					m.Raw = message.message
					decErr := m.Decode()
					if decErr != nil {
						pc.logger.Error.Println("Unable to decode STUN message:", decErr)
						break
					}
					var xorAddr stun.XORMappedAddress
					if getErr := xorAddr.GetFrom(m); getErr != nil {
						pc.logger.Error.Println("Unable to get STUN XOR address:", getErr)
						break
					}

					if stunPublicAddr.String() != xorAddr.String() {
						stunPublicAddr = xorAddr
						pc.myAddr, err = net.ResolveUDPAddr("udp4", xorAddr.String())
						sharedutils.CheckError(err)

						peerAddrChan = pc.StartConnection(foundPeer)
					}

				case string(message.message) == pingMsg:
					pc.logger.Debug.Println("Received ping from", pc.peerAddr)
					pc.lastKeepalive = time.Now()

				default:
					if message.raddr.String() == localWGAddr {
						pc.connectedOutbound = true
						n := len(message.message)
						pc.logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", pc.peerAddr, n)
						udpSend(message.message, pc.localPeerConn, pc.peerAddr)
					} else {
						pc.connectedInbound = true
						n := len(message.message)
						pc.logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", pc.wgConn.RemoteAddr(), n)
						pc.wgConn.Write(message.message)
					}

				}

			case peerStr := <-peerAddrChan:
				if pc.ShouldTryPrivate() {
					pc.logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", pc.peerID, ". This connection attempt may fail")
				} else {
					pc.logger.Info.Println("Connecting to public IP address of peer", peerStr, "for peer", pc.peerID, ". This connection attempt may fail")
				}

				pc.logger.Debug.Println("Publishing for peer join", pc.peerID)
				GLPPublish(pc.buildP2PKey(), pc.buildNetworkEndpointEvent())

				pc.peerAddr, err = net.ResolveUDPAddr(udp, peerStr)
				if err != nil {
					log.Fatalln("resolve peeraddr:", err)
				}
				conf := ""
				conf += fmt.Sprintf("public_key=%s\n", keyToHex(pc.PeerProfile.PublicKey))
				conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
				conf += "replace_allowed_ips=true\n"
				conf += fmt.Sprintf("allowed_ip=%s/32\n", pc.PeerProfile.WireguardIP.String())

				SetConfigMulti(pc.device, conf)

				pc.started = true
				pc.triedPrivate = true
				foundPeer <- true
				pc.lastKeepalive = time.Now()

			case <-keepalive:
				// Keep NAT binding alive using STUN server or the peer once it's known
				if pc.peerAddr == nil {
					pc.logger.Debug.Println("Using", pc.BindTechnique, "binding technique")
					if pc.BindTechnique == BindSTUN {
						err = sendBindingRequest(pc.localPeerConn, stunAddr)
					} else if pc.BindTechnique == BindUPNPGID {
						err = peerupnpgid.BindRequest(pc.localPeerConn, localPeerPort, messageChan)
					} else {
						err = errors.New("Unknown bind technique")
					}
				} else {
					err = udpSendStr(keepaliveMsg, pc.localPeerConn, pc.peerAddr)
				}

				if err != nil {
					pc.logger.Error.Println("keepalive:", err)
				}

				if pc.started && pc.lastKeepalive.Before(time.Now().Add(-5*time.Second)) {
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

	a := strings.Split(pc.localPeerConn.LocalAddr().String(), ":")
	return localAddr.IP.String() + ":" + a[len(a)-1]
}

func (pc *PeerConnection) buildNetworkEndpointEvent() Event {
	return Event{Type: "network_endpoint", Data: gin.H{
		"id":               pc.MyProfile.PublicKey,
		"public_endpoint":  pc.myAddr.String(),
		"private_endpoint": pc.getPrivateAddr(),
	}}
}

func (pc *PeerConnection) getPeerAddr() <-chan string {
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
	return !pc.triedPrivate
}

func (pc *PeerConnection) Connected() bool {
	return pc.connectedInbound && pc.connectedOutbound
}

func (pc *PeerConnection) StartConnection(foundPeer chan bool) <-chan string {
	pc.logger.Info.Printf("My public address for peer %s: %s. Obtained via %s\n", pc.peerID, pc.myAddr, pc.BindTechnique)

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
