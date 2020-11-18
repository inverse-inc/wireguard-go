package ztn

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"gortc.io/stun"
)

type NetworkConnection struct {
	publicAddr *net.UDPAddr

	localConn *net.UDPConn
	wgConn    *net.UDPConn

	BindTechnique BindTechnique

	peerConnections map[string]*bridge

	logger *device.Logger

	messageChan chan *pkt
}

type bridge struct {
	conn  *net.UDPConn
	raddr *net.UDPAddr
}

func NewNetworkConnection(logger *device.Logger) *NetworkConnection {
	nc := &NetworkConnection{
		logger:          logger,
		peerConnections: map[string]*bridge{},
		messageChan:     make(chan *pkt),
	}
	if bt := sharedutils.EnvOrDefault("WG_BIND_TECHNIQUE", ""); bt != "" {
		nc.BindTechnique = BindTechnique(bt)
	} else {
		nc.BindTechnique = DefaultBindTechnique
	}
	return nc
}

func (nc *NetworkConnection) Start() {
	var err error

	var stunPublicAddr stun.XORMappedAddress

	keepalive := time.Tick(500 * time.Millisecond)

	nc.localConn, err = net.ListenUDP(udp, nil)
	sharedutils.CheckError(err)

	peerupnpgid := NewUPNPGID()
	peernatpmp := NewNATPMP()

	a := strings.Split(nc.localConn.LocalAddr().String(), ":")
	localPort, err := strconv.Atoi(a[len(a)-1])
	sharedutils.CheckError(err)

	stunAddr, err := net.ResolveUDPAddr(udp, stunServer)
	sharedutils.CheckError(err)

	nc.listen(nc.localConn, nc.messageChan)

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
			case message, ok = <-nc.messageChan:
				if !ok {
					return false
				}

				switch {
				case peerupnpgid.IsMessage(message.message):
					externalIP, externalPort, err := peerupnpgid.ParseBindRequestPkt(message.message)
					if err != nil {
						nc.logger.Error.Println("Unable to decode UPNP GID message:", err)
						break
					}

					newaddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", externalIP, externalPort))
					sharedutils.CheckError(err)
					if newaddr.String() != nc.publicAddr.String() {
						nc.publicAddr = newaddr
					}
				case peernatpmp.IsMessage(message.message):
					externalIP, externalPort, err := peernatpmp.ParseBindRequestPkt(message.message)
					if err != nil {
						nc.logger.Error.Println("Unable to decode UPNP GID message:", err)
						break
					}

					newaddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", externalIP, externalPort))
					sharedutils.CheckError(err)
					if newaddr.String() != nc.publicAddr.String() {
						nc.publicAddr = newaddr
					}
				case stun.IsMessage(message.message):
					m := new(stun.Message)
					m.Raw = message.message
					decErr := m.Decode()
					if decErr != nil {
						nc.logger.Error.Println("Unable to decode STUN message:", decErr)
						break
					}
					var xorAddr stun.XORMappedAddress
					if getErr := xorAddr.GetFrom(m); getErr != nil {
						nc.logger.Error.Println("Unable to get STUN XOR address:", getErr)
						break
					}

					if stunPublicAddr.String() != xorAddr.String() {
						stunPublicAddr = xorAddr
						nc.publicAddr, err = net.ResolveUDPAddr("udp4", xorAddr.String())
						sharedutils.CheckError(err)
					}

				case string(message.message) == pingMsg:
					nc.logger.Debug.Println("Received ping from", message.raddr.String())

				default:
					if writeBack := nc.findBridge(message.conn.LocalAddr()); writeBack != nil {
						n := len(message.message)
						nc.logger.Debug.Printf("send to peer WG server: [%s]: %d bytes from %s\n", writeBack.raddr.String(), n, message.raddr)
						writeBack.conn.Write(message.message)
						udpSend(message.message, writeBack.conn, writeBack.raddr)
					} else {
						n := len(message.message)
						localWGAddr := &net.UDPAddr{IP: localWGIP, Port: localWGPort}
						writeBack := nc.setupBridge(message.conn, message.raddr, localWGAddr, nc.messageChan)
						nc.logger.Debug.Printf("send to my WG server: [%s]: %d bytes %s\n", localWGAddr.String(), n, message.raddr)
						writeBack.conn.Write(message.message)
					}
				}
			case <-keepalive:
				nc.logger.Debug.Println("Using", nc.BindTechnique, "binding technique")

				// Keep NAT binding alive using STUN server
				if nc.BindTechnique == BindSTUN {
					err = sendBindingRequest(nc.localConn, stunAddr)
				}
				if nc.publicAddr == nil {
					if nc.BindTechnique == BindUPNPGID {
						err = peerupnpgid.BindRequest(nc.localConn, localPort, nc.messageChan)
					} else if nc.BindTechnique == BindNATPMP {
						err = peernatpmp.BindRequest(nc.localConn, localPort, nc.messageChan)
					}
				}

				if err != nil {
					nc.logger.Error.Println("keepalive:", err)
				}

			}
			return true
		}()
		if !res {
			return
		}
	}
}

func (nc *NetworkConnection) GetPublicAddr() *net.UDPAddr {
	return nc.publicAddr
}

func (nc *NetworkConnection) listen(conn *net.UDPConn, messages chan *pkt) {
	go func() {
		for {
			buf := defaultBufferPool.Get()

			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			buf = buf[:n]

			messages <- &pkt{conn: conn, raddr: raddr, message: buf}
		}
	}()
}

func (nc *NetworkConnection) setupBridge(fromConn *net.UDPConn, raddr *net.UDPAddr, toAddr *net.UDPAddr, messages chan *pkt) *bridge {
	if nc.peerConnections[raddr.String()] == nil {
		conn, err := net.DialUDP("udp4", nil, toAddr)
		sharedutils.CheckError(err)
		nc.peerConnections[raddr.String()] = &bridge{conn: conn, raddr: raddr}
		nc.peerConnections[conn.LocalAddr().String()] = &bridge{conn: fromConn, raddr: raddr}
		nc.listen(conn, messages)
	}
	return nc.peerConnections[raddr.String()]
}

func (nc *NetworkConnection) findBridge(addr net.Addr) *bridge {
	return nc.peerConnections[addr.String()]
}
