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
	"golang.zx2c4.com/wireguard/device"
	"gortc.io/stun"
)

const udp = "udp"
const pingMsg = "ping"

const stunServer = "stun.l.google.com:19302"

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

	triedPrivate bool
}

func NewPeerConnection(d *device.Device, logger *device.Logger, myProfile Profile, peerProfile PeerProfile) *PeerConnection {
	pc := &PeerConnection{
		device:      d,
		logger:      logger,
		myID:        myProfile.PublicKey,
		peerID:      peerProfile.PublicKey,
		MyProfile:   myProfile,
		PeerProfile: peerProfile,
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

	var publicAddr stun.XORMappedAddress

	messageChan := make(chan *pkt)
	pc.listen(pc.localPeerConn, messageChan)
	pc.listen(pc.wgConn, messageChan)
	var peerAddrChan <-chan string

	keepalive := time.Tick(500 * time.Millisecond)
	keepaliveMsg := pingMsg

	foundPeer := make(chan bool)

	a := strings.Split(pc.localPeerConn.LocalAddr().String(), ":")
	var localPeerAddr = "127.0.0.1:" + a[len(a)-1]

	for {
		select {
		case message, ok := <-messageChan:
			if !ok {
				return
			}

			switch {
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

				if publicAddr.String() != xorAddr.String() {
					pc.logger.Info.Printf("My public address for peer %s: %s\n", pc.peerID, xorAddr)
					publicAddr = xorAddr
					pc.myAddr, err = net.ResolveUDPAddr("udp4", xorAddr.String())
					sharedutils.CheckError(err)

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

					peerAddrChan = pc.getPeerAddr()
				}

			case string(message.message) == pingMsg:
				pc.logger.Debug.Println("Received ping from", pc.peerAddr)
				pc.lastKeepalive = time.Now()

			default:
				if message.raddr.String() == "127.0.0.1:6969" {
					n := len(message.message)
					pc.logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", pc.peerAddr, n)
					udpSend(message.message, pc.localPeerConn, pc.peerAddr)
				} else {
					n := len(message.message)
					pc.logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", pc.wgConn.RemoteAddr(), n)
					pc.wgConn.Write(message.message)
				}

			}

		case peerStr := <-peerAddrChan:
			if !pc.triedPrivate {
				pc.logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", pc.peerID, ". This connection attempt may fail")
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
				err = sendBindingRequest(pc.localPeerConn, stunAddr)
			} else {
				err = udpSendStr(keepaliveMsg, pc.localPeerConn, pc.peerAddr)
			}

			if err != nil {
				pc.logger.Error.Println("keepalive:", err)
			}

			if pc.started && pc.lastKeepalive.Before(time.Now().Add(-5*time.Second)) {
				pc.logger.Error.Println("No packet or keepalive received for too long. Connection to", pc.peerID, "is dead")
				return
			}
		}
	}
}

func (pc *PeerConnection) listen(conn *net.UDPConn, messages chan *pkt) {
	go func() {
		for {
			buf := make([]byte, 1024)

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
		c.Start()
		for {
			select {
			case e := <-c.EventsChan:
				event := Event{}
				err := json.Unmarshal(e.Data, &event)
				sharedutils.CheckError(err)
				if event.Type == "network_endpoint" && event.Data["id"].(string) != myID {
					if !pc.triedPrivate {
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
