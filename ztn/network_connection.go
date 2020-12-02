package ztn

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/theckman/go-securerandom"
	"gortc.io/stun"
)

type bridge struct {
	conn      *net.UDPConn
	raddr     *net.UDPAddr
	lastUsed  time.Time
	autoClose bool
	marker    []byte
}

type pkt struct {
	conn    *net.UDPConn
	raddr   *net.UDPAddr
	message []byte
}

type NetworkConnection struct {
	description string

	Connection *Connection

	id    uint64
	token uint64

	publicAddr *net.UDPAddr

	publicAddrChan chan *net.UDPAddr

	bindThroughPeerAddr *net.UDPAddr

	localConn *net.UDPConn
	port      int

	BindTechnique  BindTechnique
	BindTechniques *BindTechniquesStruct

	peerConnections map[string]*bridge

	logger *device.Logger

	messageChan chan *pkt

	printDebugChan chan bool

	inboundAttempts     int
	inboundAttemptsChan chan int

	stopForwardingPing chan bool

	started        time.Time
	lastWGInbound  time.Time
	lastWGOutbound time.Time

	WGAddr       *net.UDPAddr
	wgRemoteConn *net.UDPConn
	wgConnRemote bool
}

func NewNetworkConnection(description string, logger *device.Logger, port int) *NetworkConnection {
	nc := &NetworkConnection{
		logger:          logger.AddPrepend(fmt.Sprintf("(NC:%s) ", description)),
		peerConnections: map[string]*bridge{},
		port:            port,
	}
	nc.WGAddr = &net.UDPAddr{IP: localWGIP, Port: localWGPort}

	var err error
	nc.id, err = securerandom.Uint64()
	sharedutils.CheckError(err)
	nc.token, err = securerandom.Uint64()
	sharedutils.CheckError(err)

	nc.reset()
	nc.BindTechniques = BindTechniques.CopyNew()
	if bt := sharedutils.EnvOrDefault("WG_BIND_TECHNIQUE", ""); bt != "" && BindTechniqueNames[bt] != "" {
		nc.BindTechnique = BindTechniqueNames[bt]
	} else {
		nc.BindTechnique = nc.BindTechniques.Next()
	}

	return nc
}

func (nc *NetworkConnection) reset() {
	nc.publicAddr = nil

	nc.bindThroughPeerAddr = nil

	if nc.localConn != nil {
		nc.localConn.Close()
	}
	for _, pc := range nc.peerConnections {
		pc.conn.Close()
	}
	nc.peerConnections = map[string]*bridge{}

	nc.messageChan = make(chan *pkt)

	nc.printDebugChan = make(chan bool)

	nc.inboundAttempts = 0
	nc.inboundAttemptsChan = make(chan int)

	nc.started = time.Time{}
	nc.lastWGInbound = time.Time{}
	nc.lastWGOutbound = time.Time{}

	nc.wgRemoteConn = nil

	if nc.stopForwardingPing != nil {
		go func() {
			nc.stopForwardingPing <- true
		}()
	}
	nc.stopForwardingPing = make(chan bool)
}

func (nc *NetworkConnection) Start() {
	for {
		nc.run()
		nc.reset()
		nc.logger.Info.Println("Public network connection seems to be inactive, will open a new public port")
	}
}

func (nc *NetworkConnection) SetupForwarding(ct string) (net.Addr, *net.UDPAddr) {
	nc.publicAddrChan = make(chan *net.UDPAddr)

	go nc.run()

	select {
	case <-time.After(5 * time.Second):
		return nil, nil
	case addr := <-nc.publicAddrChan:
		// If our peer wants the LAN address or the WAN address to talk to us
		// And also what is the address to advertise to his own peers
		if ct == ConnectionTypeLAN {
			return nc.localConn.LocalAddr(), addr
		} else {
			return addr, addr
		}
	}
}

func (nc *NetworkConnection) run() {
	var err error

	var stunPublicAddr stun.XORMappedAddress

	keepalive := time.Tick(500 * time.Millisecond)

	maintenance := time.Tick(1 * time.Minute)

	var localConnAddr *net.UDPAddr
	if nc.port != 0 {
		localConnAddr, err = net.ResolveUDPAddr(udp, fmt.Sprintf(":%d", nc.port))
		sharedutils.CheckError(err)
	}

	nc.localConn, err = net.ListenUDP(udp, localConnAddr)
	sharedutils.CheckError(err)

	peerupnpigd := NewUPNPIGD()
	peernatpmp := NewNATPMP()
	peerbindthroughpeer := NewBindThroughPeerAgent(nc.Connection, nc)

	peerbindthroughpeerCheck := time.Tick(2 * time.Second)

	a := strings.Split(nc.localConn.LocalAddr().String(), ":")
	localPort, err := strconv.Atoi(a[len(a)-1])
	sharedutils.CheckError(err)

	stunAddr, err := net.ResolveUDPAddr(udp, stunServer)
	sharedutils.CheckError(err)

	nc.listen(nc.localConn, nc.messageChan)

	nc.started = time.Now()

	for {
		res := func() bool {
			err = nil
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
				case nc.IsMessage(message.message):
					nc.handleMessage(message.conn, message.raddr, message.message)
				case peerbindthroughpeer.IsMessage(message.message):
					externalIP, externalPort, err := peerbindthroughpeer.ParseBindRequestPkt(message.message)
					if err != nil {
						nc.logger.Error.Println("Unable to decode Bind through peer message:", err)
						return false
					}

					newaddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", externalIP, externalPort))
					sharedutils.CheckError(err)
					if newaddr.String() != nc.publicAddr.String() {
						nc.setPublicAddr(newaddr)
					}

				case peerupnpigd.IsMessage(message.message):
					externalIP, externalPort, err := peerupnpigd.ParseBindRequestPkt(message.message)
					if err != nil {
						nc.logger.Error.Println("Unable to decode UPNP GID message:", err)
						return false
					}

					newaddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", externalIP, externalPort))
					sharedutils.CheckError(err)
					if newaddr.String() != nc.publicAddr.String() {
						nc.setPublicAddr(newaddr)
					}
				case peernatpmp.IsMessage(message.message):
					externalIP, externalPort, err := peernatpmp.ParseBindRequestPkt(message.message)
					if err != nil {
						nc.logger.Error.Println("Unable to decode UPNP GID message:", err)
						return false
					}

					newaddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", externalIP, externalPort))
					sharedutils.CheckError(err)
					if newaddr.String() != nc.publicAddr.String() {
						nc.setPublicAddr(newaddr)
					}
				case stun.IsMessage(message.message):
					m := new(stun.Message)
					m.Raw = message.message
					decErr := m.Decode()
					if decErr != nil {
						nc.logger.Error.Println("Unable to decode STUN message:", decErr)
						return false
					}
					var xorAddr stun.XORMappedAddress
					if getErr := xorAddr.GetFrom(m); getErr != nil {
						nc.logger.Error.Println("Unable to get STUN XOR address:", getErr)
						return false
					}

					if stunPublicAddr.String() != xorAddr.String() {
						stunPublicAddr = xorAddr
						newaddr, err := net.ResolveUDPAddr("udp4", xorAddr.String())
						sharedutils.CheckError(err)
						nc.setPublicAddr(newaddr)
					}

				case string(message.message) == pingMsg:
					nc.logger.Debug.Println("Received ping from", message.raddr.String())

				default:
					if writeBack := nc.findBridge(message.conn.LocalAddr()); writeBack != nil {
						msg := message.message
						nc.lastWGOutbound = time.Now()
						if nc.BindTechnique == BindThroughPeer {
							msg = nc.addMarker(writeBack.marker, msg)
						}
						n := len(message.message)
						nc.logger.Debug.Printf("send to peer WG server: [%s]: %d bytes from %s (marker:%s)\n", writeBack.raddr.String(), n, message.raddr, nc.infoFromMarker(writeBack.marker))
						udpSend(msg, writeBack.conn, writeBack.raddr)
						if err != nil {
							nc.logger.Error.Printf("Error sending packet to peer %s from WG server %s: %s", writeBack.raddr.String(), message.raddr, err)
						}
					} else if writeBack := nc.findRemoteBridge(message.conn.LocalAddr(), message.message); writeBack != nil {
						nc.lastWGOutbound = time.Now()
						n := len(message.message)

						// strip our special header
						_, msg := nc.stripMarker(message.message)

						nc.logger.Debug.Printf("send to remote peer WG server: [%s]: %d bytes from %s\n", writeBack.raddr.String(), n, message.raddr)
						udpSend(msg, writeBack.conn, writeBack.raddr)
						if err != nil {
							nc.logger.Error.Printf("Error sending packet to peer %s from WG server %s: %s", writeBack.raddr.String(), message.raddr, err)
						}
					} else {
						//TODO: more mem efficiency and ensure garbage collected
						nc.lastWGInbound = time.Now()
						n := len(message.message)
						if nc.wgConnRemote {
							nc.setupRemoteBridge(message.conn, message.raddr)
							msg := nc.addMarkerFromAddr(message.raddr, message.message)
							nc.logger.Debug.Printf("send to remote WG server: [%s]: %d bytes from %s\n", nc.WGAddr.String(), n, message.raddr)
							err = udpSend(msg, nc.wgRemoteConn, nc.WGAddr)
						} else {
							var marker []byte
							msg := message.message
							if nc.BindTechnique == BindThroughPeer {
								marker, msg = nc.stripMarker(message.message)
							}
							writeBack := nc.setupBridge(message.conn, message.raddr, nc.WGAddr, nc.messageChan, marker)
							// recompute length so that its refreshed if a marker was removed
							n = len(msg)
							nc.logger.Debug.Printf("send to my WG server: [%s]: %d bytes from %s (marker:%s)\n", nc.WGAddr.String(), n, message.raddr, nc.infoFromMarker(marker))
							_, err = writeBack.conn.Write(msg)
						}
						if err != nil {
							nc.logger.Error.Printf("Error sending packet to WG server %s from peer %s: %s", nc.WGAddr.String(), message.raddr, err)
						}
					}
				}
			case <-nc.inboundAttemptsChan:
				nc.inboundAttempts++
				nc.logger.Debug.Println("Got an inbound attempt reported by a peer connection", nc.inboundAttempts, InboundAttemptsTolerance, time.Since(nc.started), InboundAttemptsTryAtLeast, nc.lastWGInbound)
				if nc.inboundAttempts > InboundAttemptsTolerance && time.Since(nc.started) > InboundAttemptsTryAtLeast && nc.lastWGInbound.IsZero() {
					nc.BindTechnique = nc.BindTechniques.Next()
					return false
				}
			case <-nc.printDebugChan:
				nc.logger.Info.Print(spew.Sdump(nc.peerConnections))
				nc.logger.Info.Println("Last inbound/outbound", nc.lastWGInbound, "/", nc.lastWGOutbound)
			case <-maintenance:
				nc.maintenance()
			case <-peerbindthroughpeerCheck:
				if nc.BindTechnique == BindThroughPeer && nc.publicAddr != nil && nc.publicAddr.Port != 0 {
					if !peerbindthroughpeer.StillAlive() {
						nc.logger.Info.Println("Lost connection in bind through peer")
						return false
					}
				}
			case <-keepalive:
				if !nc.CheckConnectionLiveness() {
					if peerupnpigd.remotePort != 0 {
						peerupnpigd.DelPortMapping()
					}
					nc.BindTechnique = nc.BindTechniques.Next()
					return false
				}

				nc.logger.Debug.Println("Using", nc.BindTechnique, "binding technique")

				// Keep NAT binding alive using STUN server
				if nc.BindTechnique == BindSTUN {
					err = sendBindingRequest(nc.localConn, stunAddr)
				}
				if nc.BindTechnique == BindThroughPeer && (nc.publicAddr == nil || nc.publicAddr.Port == 0) {
					err = peerbindthroughpeer.BindRequest(nc.localConn, nc.messageChan)
				}
				if nc.publicAddr == nil {
					if nc.BindTechnique == BindUPNPIGD {
						err = peerupnpigd.BindRequest(nc.localConn, localPort, nc.messageChan)
					} else if nc.BindTechnique == BindNATPMP {
						err = peernatpmp.BindRequest(nc.localConn, localPort, nc.messageChan)
					}
				}

				if nc.wgConnRemote {
					udpSend([]byte(pingMsg), nc.wgRemoteConn, nc.WGAddr)
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

func (nc *NetworkConnection) setupBridge(fromConn *net.UDPConn, raddr *net.UDPAddr, toAddr *net.UDPAddr, messages chan *pkt, marker []byte) *bridge {
	if nc.peerConnections[raddr.String()] == nil {
		conn, err := net.DialUDP("udp4", nil, toAddr)
		sharedutils.CheckError(err)
		markerCopy := make([]byte, len(marker))
		copy(markerCopy, marker)
		nc.peerConnections[raddr.String()] = &bridge{conn: conn, raddr: raddr, marker: markerCopy}
		nc.peerConnections[conn.LocalAddr().String()] = &bridge{conn: fromConn, raddr: raddr, marker: markerCopy}
		nc.listen(conn, messages)
	}
	return nc.peerConnections[raddr.String()]
}

func (nc *NetworkConnection) findBridge(addr net.Addr) *bridge {
	b := nc.peerConnections[addr.String()]
	if b != nil {
		b.lastUsed = time.Now()
	}
	return b
}

const remotePrefix = "remote:"
const remoteBackSuffix = ":back"
const markerLength = 4 + binary.MaxVarintLen64

func (nc *NetworkConnection) setupRemoteBridge(fromConn *net.UDPConn, raddr *net.UDPAddr) {
	if nc.peerConnections[remotePrefix+raddr.String()] == nil {
		conn := nc.wgRemoteConn
		nc.peerConnections[remotePrefix+raddr.String()] = &bridge{conn: conn, raddr: raddr}
		nc.peerConnections[remotePrefix+raddr.String()+remoteBackSuffix] = &bridge{conn: fromConn, raddr: raddr}
	}
}

func (nc *NetworkConnection) findRemoteBridge(addr net.Addr, message []byte) *bridge {
	if nc.wgRemoteConn == nil {
		return nil
	}

	conn := addr.(*net.UDPAddr)
	if conn.IP.Equal(nc.wgRemoteConn.LocalAddr().(*net.UDPAddr).IP) && conn.Port == nc.wgRemoteConn.LocalAddr().(*net.UDPAddr).Port {
		if nc.wgConnRemote {
			raddr := nc.infoFromMarker(message)
			return nc.peerConnections[remotePrefix+raddr.String()+remoteBackSuffix]
		}
	}
	return nil
}

func (nc *NetworkConnection) CheckConnectionLiveness() bool {
	if time.Since(nc.started) > PublicPortLivenessTolerance {
		if time.Since(nc.lastWGInbound) > PublicPortLivenessTolerance || time.Since(nc.lastWGOutbound) > PublicPortLivenessTolerance {
			nc.logger.Info.Println("Have not processed a public packet for too long on the public port.", "Last inbound", nc.lastWGInbound, ", last outbound", nc.lastWGOutbound)
			return false
		}
	}
	return true
}

func (nc *NetworkConnection) RecordInboundAttempt() {
	nc.inboundAttemptsChan <- 1
}

func (nc *NetworkConnection) PrintDebug() {
	nc.printDebugChan <- true
}

func (nc *NetworkConnection) maintenance() {
	toDel := []string{}
	for raddr, br := range nc.peerConnections {
		if time.Since(br.lastUsed) > PublicPortLivenessTolerance {
			if br.autoClose {
				nc.logger.Info.Println("Closing inactive connection to", raddr)
				br.conn.Close()
			} else {
				nc.logger.Debug.Println("Deleting inactive peer connection to", raddr)
			}
			toDel = append(toDel, raddr)
		}
	}
	for _, raddr := range toDel {
		delete(nc.peerConnections, raddr)
	}
}

func (nc *NetworkConnection) setPublicAddr(addr *net.UDPAddr) {
	nc.publicAddr = addr
	if nc.publicAddrChan != nil {
		nc.publicAddrChan <- addr
	}
}

func (nc *NetworkConnection) ID() uint64 {
	return nc.id
}

func (nc *NetworkConnection) Token() uint64 {
	return nc.token
}

func (nc *NetworkConnection) Description() string {
	return nc.description
}

func (nc *NetworkConnection) IsMessage(b []byte) bool {
	id, _ := binary.Uvarint(b[:binary.MaxVarintLen64])
	if id == nc.id {
		return true
	} else {
		return false
	}
}

func (nc *NetworkConnection) handleMessage(conn *net.UDPConn, raddr *net.UDPAddr, b []byte) bool {
	id, _ := binary.Uvarint(b[:binary.MaxVarintLen64])
	token, _ := binary.Uvarint(b[1*binary.MaxVarintLen64 : 2*binary.MaxVarintLen64])
	msgType, _ := binary.Uvarint(b[2*binary.MaxVarintLen64 : 3*binary.MaxVarintLen64])
	data := b[3*binary.MaxVarintLen64:]

	if id != nc.id {
		nc.logger.Error.Println("Tried to handle a message that doesn't have the right ID")
		return true
	}

	if token != nc.token {
		nc.logger.Info.Println("Stopped handling a message that doesn't have a valid token")
		return true
	}

	handlers := map[uint64]func(conn *net.UDPConn, raddr *net.UDPAddr, id, token, msgType uint64, data []byte) bool{
		MsgNcBindPeerBridge: nc.bindPeerBridge,
	}

	if h, ok := handlers[msgType]; ok {
		return h(conn, raddr, id, token, msgType, data)
	} else {
		nc.logger.Error.Println("Received unknown message type", msgType)
		return true
	}
}

func (nc *NetworkConnection) bindPeerBridge(conn *net.UDPConn, raddr *net.UDPAddr, id, token, msgType uint64, data []byte) bool {
	nc.logger.Info.Println("Setting up peer bridge to", raddr)
	nc.WGAddr = raddr
	nc.wgRemoteConn = conn
	nc.wgConnRemote = true
	udpSend([]byte(pingMsg), conn, raddr)
	//nc.listen(nc.wgRemoteConn, nc.messageChan)
	return true
}

func (nc *NetworkConnection) addMarkerFromAddr(raddr *net.UDPAddr, data []byte) []byte {
	info := []byte{raddr.IP[12], raddr.IP[13], raddr.IP[14], raddr.IP[15]}
	port := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(port, uint64(raddr.Port))
	info = append(info, port...)
	return nc.addMarker(info, data)
}

func (nc *NetworkConnection) addMarker(marker []byte, data []byte) []byte {
	//TODO: this needs to be optimized
	return append(marker, data...)
}

func (nc *NetworkConnection) infoFromMarker(message []byte) *net.UDPAddr {
	if nc.wgConnRemote || nc.BindTechnique == BindThroughPeer {
		port, _ := binary.Uvarint(message[4 : 4+binary.MaxVarintLen64])
		return &net.UDPAddr{
			IP:   net.IPv4(message[0], message[1], message[2], message[3]),
			Port: int(port),
		}
	}
	return nil
}

func (nc *NetworkConnection) stripMarker(message []byte) ([]byte, []byte) {
	//TODO: this needs to be optimized
	return message[:markerLength], message[markerLength:]
}
