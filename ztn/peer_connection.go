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

const orchestrationServer = "http://srv.semaan.ca:6969"
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

func (p *PeerConnection) run() {
	var err error
	p.wgConn, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: localWGIP, Port: localWGPort})
	sharedutils.CheckError(err)

	stunAddr, err := net.ResolveUDPAddr(udp, stunServer)
	sharedutils.CheckError(err)

	p.localPeerConn, err = net.ListenUDP(udp, nil)
	sharedutils.CheckError(err)

	p.logger.Debug.Printf("Listening on %s for peer %s\n", p.localPeerConn.LocalAddr(), p.peerID)

	var publicAddr stun.XORMappedAddress

	messageChan := make(chan *pkt)
	p.listen(p.localPeerConn, messageChan)
	p.listen(p.wgConn, messageChan)
	var peerAddrChan <-chan string

	keepalive := time.Tick(500 * time.Millisecond)
	keepaliveMsg := pingMsg

	foundPeer := make(chan bool)

	a := strings.Split(p.localPeerConn.LocalAddr().String(), ":")
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
					log.Println("decode:", decErr)
					break
				}
				var xorAddr stun.XORMappedAddress
				if getErr := xorAddr.GetFrom(m); getErr != nil {
					log.Println("getFrom:", getErr)
					break
				}

				if publicAddr.String() != xorAddr.String() {
					p.logger.Info.Printf("My public address for peer %s: %s\n", p.peerID, xorAddr)
					publicAddr = xorAddr
					p.myAddr, err = net.ResolveUDPAddr("udp4", xorAddr.String())
					sharedutils.CheckError(err)

					go func() {
						for {
							select {
							case <-time.After(1 * time.Second):
								p.logger.Info.Println("Publishing IP for discovery with peer", p.peerID)
								glpPublish(p.buildP2PKey(), p.buildPublicEndpointEvent())
							case <-foundPeer:
								p.logger.Info.Println("Found peer", p.peerID, ", stopping the publishing")
								return
							}
						}
					}()

					peerAddrChan = p.getPeerAddr()
				}

			case string(message.message) == pingMsg:
				p.logger.Debug.Println("Received ping from", p.peerAddr)
				p.lastKeepalive = time.Now()

			default:
				if message.raddr.String() == "127.0.0.1:6969" {
					n := len(message.message)
					p.logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", p.peerAddr, n)
					udpSend(message.message, p.localPeerConn, p.peerAddr)
				} else {
					n := len(message.message)
					p.logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", p.wgConn.RemoteAddr(), n)
					p.wgConn.Write(message.message)
				}

			}

		case peerStr := <-peerAddrChan:
			p.logger.Info.Println("Publishing for peer join", p.peerID)
			glpPublish(p.buildP2PKey(), p.buildPublicEndpointEvent())

			p.peerAddr, err = net.ResolveUDPAddr(udp, peerStr)
			if err != nil {
				log.Fatalln("resolve peeraddr:", err)
			}
			conf := ""
			conf += fmt.Sprintf("public_key=%s\n", keyToHex(p.PeerProfile.PublicKey))
			conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
			conf += "replace_allowed_ips=true\n"
			conf += fmt.Sprintf("allowed_ip=%s/32\n", p.PeerProfile.WireguardIP.String())

			fmt.Println(conf)

			SetConfigMulti(p.device, conf)

			p.started = true
			foundPeer <- true
			p.lastKeepalive = time.Now()

		case <-keepalive:
			// Keep NAT binding alive using STUN server or the peer once it's known
			if p.peerAddr == nil {
				err = sendBindingRequest(p.localPeerConn, stunAddr)
			} else {
				err = udpSendStr(keepaliveMsg, p.localPeerConn, p.peerAddr)
			}

			if err != nil {
				p.logger.Error.Println("keepalive:", err)
			}

			if p.started && p.lastKeepalive.Before(time.Now().Add(-5*time.Second)) {
				p.logger.Error.Println("No packet or keepalive received for too long. Connection to", p.peerID, "is dead")
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

func (pc *PeerConnection) buildPublicEndpointEvent() Event {
	return Event{Type: "public_endpoint", Data: gin.H{"id": pc.MyProfile.PublicKey, "public_endpoint": pc.myAddr.String()}}
}

func (pc *PeerConnection) getPeerAddr() <-chan string {
	result := make(chan string)
	myID := pc.MyProfile.PublicKey

	p2pk := pc.buildP2PKey()

	go func() {
		c := glpClient(p2pk)
		c.Start()
		for {
			select {
			case e := <-c.EventsChan:
				event := Event{}
				err := json.Unmarshal(e.Data, &event)
				sharedutils.CheckError(err)
				if event.Type == "public_endpoint" && event.Data["id"].(string) != myID {
					result <- event.Data["public_endpoint"].(string)
					return
				}
			}
		}
	}()

	return result
}
