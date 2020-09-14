package natt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn/api"
	"github.com/inverse-inc/wireguard-go/ztn/bufferpool"
	"github.com/inverse-inc/wireguard-go/ztn/config"
	"github.com/inverse-inc/wireguard-go/ztn/constants"
	"github.com/inverse-inc/wireguard-go/ztn/profile"
	"github.com/inverse-inc/wireguard-go/ztn/util"

	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"gortc.io/stun"
)

const udp = "udp"
const pingMsg = "ping"

const stunServer = "stun.l.google.com:19302"

type pkt struct {
	raddr   *net.UDPAddr
	message []byte
}

// STUN struct
type STUN struct {
	ConnectionPeer *ExternalConnection
}

//NewSTUN init
func NewSTUN(ctx context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) (Method, error) {
	method := STUN{}
	method.init(ctx, d, logger, myProfile, peerProfile)
	return &method, nil
}

// Init function
func (natt *STUN) init(context context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) {
	log.SetProcessName("wireguard-go")
	ctx := log.LoggerNewContext(context)
	e := &ExternalConnection{
		Device:      d,
		Logger:      logger,
		myID:        myProfile.PublicKey,
		PeerID:      peerProfile.PublicKey,
		MyProfile:   myProfile,
		PeerProfile: peerProfile,
		Ctx:         ctx,
	}
	natt.ConnectionPeer = e
}

// Run function
func (natt *STUN) Run() error {
	var err error
	natt.ConnectionPeer.WgConn, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: constants.LocalWGIP, Port: constants.LocalWGPort})
	sharedutils.CheckError(err)

	stunAddr, err := net.ResolveUDPAddr(udp, stunServer)
	sharedutils.CheckError(err)

	natt.ConnectionPeer.LocalPeerConn, err = net.ListenUDP(udp, nil)
	sharedutils.CheckError(err)

	natt.ConnectionPeer.Logger.Debug.Printf("Listening on %s for peer %s\n", natt.ConnectionPeer.LocalPeerConn.LocalAddr(), natt.ConnectionPeer.PeerID)

	var publicAddr stun.XORMappedAddress

	messageChan := make(chan *pkt)
	natt.ConnectionPeer.Listen(natt.ConnectionPeer.LocalPeerConn, messageChan)
	natt.ConnectionPeer.Listen(natt.ConnectionPeer.WgConn, messageChan)
	var peerAddrChan <-chan string
	keepalive := time.Tick(500 * time.Millisecond)
	keepaliveMsg := pingMsg

	foundPeer := make(chan bool)

	a := strings.Split(natt.ConnectionPeer.LocalPeerConn.LocalAddr().String(), ":")
	var localPeerAddr = fmt.Sprintf("%s:%s", constants.LocalWGIP.String(), a[len(a)-1])
	var localWGAddr = fmt.Sprintf("%s:%d", constants.LocalWGIP.String(), constants.LocalWGPort)

	for {
		res := func() bool {
			var message *pkt
			var ok bool

			defer func() {
				if message != nil {
					bufferpool.DefaultBufferPool.Put(message.message)
				}
			}()

			select {
			case message, ok = <-messageChan:
				if !ok {
					return false
				}

				switch {
				case stun.IsMessage(message.message):
					m := new(stun.Message)
					m.Raw = message.message
					decErr := m.Decode()
					if decErr != nil {
						natt.ConnectionPeer.Logger.Error.Println("Unable to decode STUN message:", decErr)
						break
					}
					var xorAddr stun.XORMappedAddress
					if getErr := xorAddr.GetFrom(m); getErr != nil {
						natt.ConnectionPeer.Logger.Error.Println("Unable to get STUN XOR address:", getErr)
						break
					}

					if publicAddr.String() != xorAddr.String() {
						natt.ConnectionPeer.Logger.Info.Printf("My public address for peer %s: %s\n", natt.ConnectionPeer.PeerID, xorAddr)
						publicAddr = xorAddr
						natt.ConnectionPeer.MyAddr, err = net.ResolveUDPAddr("udp4", xorAddr.String())
						sharedutils.CheckError(err)

						go func() {
							for {
								select {
								case <-time.After(1 * time.Second):
									natt.ConnectionPeer.Logger.Debug.Println("Publishing IP for discovery with peer", natt.ConnectionPeer.PeerID)
									api.GLPPublish(natt.ConnectionPeer.BuildP2PKey(), natt.ConnectionPeer.BuildNetworkEndpointEvent(natt))
								case <-foundPeer:
									natt.ConnectionPeer.Logger.Info.Println("Found peer", natt.ConnectionPeer.PeerID, ", stopping the publishing")
									return
								}
							}
						}()

						peerAddrChan = natt.ConnectionPeer.GetPeerAddr()
					}

				case string(message.message) == pingMsg:
					natt.ConnectionPeer.Logger.Debug.Println("Received ping from", natt.ConnectionPeer.PeerAddr)
					natt.ConnectionPeer.LastKeepalive = time.Now()
					natt.ConnectionPeer.Connected = true

				default:
					if message.raddr.String() == localWGAddr {
						n := len(message.message)
						natt.ConnectionPeer.Logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", natt.ConnectionPeer.PeerAddr, n)
						util.UdpSend(message.message, natt.ConnectionPeer.LocalPeerConn, natt.ConnectionPeer.PeerAddr)
					} else {
						n := len(message.message)
						natt.ConnectionPeer.Logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", natt.ConnectionPeer.WgConn.RemoteAddr(), n)
						natt.ConnectionPeer.WgConn.Write(message.message)
					}

				}

			case peerStr := <-peerAddrChan:
				if natt.ConnectionPeer.ShouldTryPrivate() {
					natt.ConnectionPeer.Logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", natt.ConnectionPeer.PeerID, ". This connection attempt may fail")
				}

				natt.ConnectionPeer.Logger.Debug.Println("Publishing for peer join", natt.ConnectionPeer.PeerID)
				api.GLPPublish(natt.ConnectionPeer.BuildP2PKey(), natt.ConnectionPeer.BuildNetworkEndpointEvent(natt))

				natt.ConnectionPeer.PeerAddr, err = net.ResolveUDPAddr(udp, peerStr)
				if err != nil {
					// pc.Logger.Fatalln("resolve peeraddr:", err)
				}
				conf := ""
				conf += fmt.Sprintf("public_key=%s\n", util.KeyToHex(natt.ConnectionPeer.PeerProfile.PublicKey))
				conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
				conf += "replace_allowed_ips=true\n"
				conf += fmt.Sprintf("allowed_ip=%s/32\n", natt.ConnectionPeer.PeerProfile.WireguardIP.String())

				config.SetConfigMulti(natt.ConnectionPeer.Device, conf)

				natt.ConnectionPeer.Started = true
				natt.ConnectionPeer.TriedPrivate = true
				foundPeer <- true
				natt.ConnectionPeer.LastKeepalive = time.Now()

			case <-keepalive:
				// Keep NAT binding alive using STUN server or the peer once it's known
				if natt.ConnectionPeer.PeerAddr == nil {
					err = util.SendBindingRequest(natt.ConnectionPeer.LocalPeerConn, stunAddr)
				} else {
					err = util.UdpSendStr(keepaliveMsg, natt.ConnectionPeer.LocalPeerConn, natt.ConnectionPeer.PeerAddr)
				}

				if err != nil {
					natt.ConnectionPeer.Logger.Error.Println("keepalive:", err)
				}

				if natt.ConnectionPeer.Started && natt.ConnectionPeer.LastKeepalive.Before(time.Now().Add(-5*time.Second)) {
					natt.ConnectionPeer.Logger.Error.Println("No packet or keepalive received for too long. Connection to", natt.ConnectionPeer.PeerID, "is dead")
					return false
				}
			}
			return true
		}()
		if !res {
			return errors.New("Stun method error")
		}
	}
}

func (natt *STUN) Start() error {
	var err error
	for {
		err = natt.Run()
		natt.ConnectionPeer.reset()
		natt.ConnectionPeer.Logger.Error.Println("Lost connection with", natt.ConnectionPeer.PeerID, ". Reconnecting")
	}
	return err
}

func (natt *STUN) GetPrivateAddr() string {
	conn, err := net.Dial("udp", stunServer)
	if err != nil {
		natt.ConnectionPeer.Logger.Error.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	a := strings.Split(natt.ConnectionPeer.LocalPeerConn.LocalAddr().String(), ":")
	return localAddr.IP.String() + ":" + a[len(a)-1]
}
