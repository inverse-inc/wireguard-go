package ztn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/util"
)

type BindThroughPeerAgent struct {
	sync.Mutex
	id                []byte
	connection        *Connection
	networkConnection *NetworkConnection
	remoteIP          net.IP
	remotePort        int
	remoteID          uint64
	remoteToken       uint64
	remotePSC         string
}

func NewBindThroughPeerAgent(connection *Connection, networkConnection *NetworkConnection) *BindThroughPeerAgent {
	btp := &BindThroughPeerAgent{
		connection:        connection,
		networkConnection: networkConnection,
	}
	btp.id = make([]byte, 64)
	_, err := rand.Read(btp.id)
	sharedutils.CheckError(err)
	return btp
}

func (btp *BindThroughPeerAgent) findBridgeablePeers() []*PeerConnection {
	btp.connection.Lock()
	defer btp.connection.Unlock()
	pcs := []*PeerConnection{}
	for _, pc := range btp.connection.Peers {
		if pc.offersBridging && pc.Connected() {
			pcs = append(pcs, pc)
		}
	}
	return pcs
}

func (btp *BindThroughPeerAgent) BindRequest(conn *net.UDPConn, sendTo chan *pkt) error {
	btp.Lock()
	defer btp.Unlock()

	if btp.remotePort != 0 {
		return nil
	}

	hostname, err := os.Hostname()
	sharedutils.CheckError(err)

	pcs := btp.findBridgeablePeers()
	for _, pc := range pcs {
		btp.networkConnection.logger.Info.Println("Attempting to setup forwarding with peer", pc.PeerProfile.WireguardIP)

		serverAddr := fmt.Sprintf("%s:%d", pc.PeerProfile.WireguardIP.String(), PeerServiceServerPort)
		c := ConnectPeerServiceClient(serverAddr)
		res, err := c.SetupForwarding(context.Background(), &SetupForwardingRequest{Name: hostname, PeerConnectionType: pc.ConnectionType})
		if err != nil {
			btp.networkConnection.logger.Error.Println("Failed to setup forwarding with peer", pc.PeerProfile.WireguardIP, "due to the following error:", err)
			continue
		}

		addr, err := net.ResolveUDPAddr("udp4", res.Raddr)
		sharedutils.CheckError(err)

		data := make([]byte, 1024)
		binary.PutUvarint(data, res.Id)
		binary.PutUvarint(data[binary.MaxVarintLen64:], res.Token)
		binary.PutUvarint(data[2*binary.MaxVarintLen64:], MsgNcBindPeerBridge)

		util.UDPSend(data, conn, addr)
		if err != nil {
			btp.networkConnection.logger.Error.Println("Failed to write to", addr, "via connection", conn, "due to the following error:", err)
			continue
		} else {
			btp.remoteIP = net.IPv4(res.PublicIP[0], res.PublicIP[1], res.PublicIP[2], res.PublicIP[3])
			btp.remotePort = int(res.PublicPort)

			btp.remotePSC = serverAddr
			btp.remoteID = res.Id
			btp.remoteToken = res.Token

			go func() {
				sendTo <- &pkt{message: btp.BindRequestPkt(btp.remoteIP, btp.remotePort)}
			}()
			return nil
		}

	}

	go func() {
		sendTo <- &pkt{message: btp.BindRequestPkt(net.IPv4(0, 0, 0, 0), 0)}
	}()
	return errors.New("Couldn't find a peer to bridge through")
}

func (btp *BindThroughPeerAgent) BindRequestPkt(externalIP net.IP, externalPort int) []byte {
	var buf = defaultBufferPool.Get()
	for i, v := range btp.id {
		buf[i] = v
	}
	buf[len(btp.id)+1] = externalIP[12]
	buf[len(btp.id)+2] = externalIP[13]
	buf[len(btp.id)+3] = externalIP[14]
	buf[len(btp.id)+4] = externalIP[15]
	binary.PutUvarint(buf[len(btp.id)+5:], uint64(externalPort))
	return buf
}

func (btp *BindThroughPeerAgent) IsMessage(b []byte) bool {
	if len(b) < len(btp.id) {
		return false
	}

	for i := 0; i < len(btp.id); i++ {
		if b[i] != btp.id[i] {
			return false
		}
	}

	return true
}

func (btp *BindThroughPeerAgent) ParseBindRequestPkt(buf []byte) (net.IP, int, error) {
	ip := net.IPv4(buf[len(btp.id)+1], buf[len(btp.id)+2], buf[len(btp.id)+3], buf[len(btp.id)+4])
	port, _ := binary.Uvarint(buf[len(btp.id)+5:])
	return ip, int(port), nil
}

func (btp *BindThroughPeerAgent) StillAlive() bool {
	btp.Lock()
	defer btp.Unlock()
	c := ConnectPeerServiceClient(btp.remotePSC)
	res, err := c.ForwardingIsAlive(context.Background(), &ForwardingIsAliveRequest{Id: btp.remoteID, Token: btp.remoteToken})
	if err != nil {
		btp.networkConnection.logger.Error.Println("Unable to connect to remote BTP peer", btp.remotePSC, ". Error:", err)
		return false
	}

	if res.Result {
		btp.networkConnection.logger.Debug.Println("Still connected to remote BTP peer", btp.remotePSC)
		return true
	} else {
		btp.networkConnection.logger.Error.Println("Remote BTP peer", btp.remotePSC, "reported the forwarding is now inactive")
		return false
	}
}
