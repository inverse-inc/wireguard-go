package ztn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/util"
)

type BindThroughPeer struct {
	id                [64]byte
	connection        *Connection
	networkConnection *NetworkConnection
}

func NewBindThroughPeer(connection *Connection, networkConnection *NetworkConnection) *BindThroughPeer {
	btp := &BindThroughPeer{
		connection:        connection,
		networkConnection: networkConnection,
	}
	return btp
}

func (btp *BindThroughPeer) findBridgeablePeers() []*PeerConnection {
	btp.connection.Lock()
	defer btp.connection.Unlock()
	pcs := []*PeerConnection{}
	for _, pc := range btp.connection.Peers {
		if pc.offersBridging {
			pcs = append(pcs, pc)
		}
	}
	return pcs
}

func (btp *BindThroughPeer) BindRequest(conn *net.UDPConn, sendTo chan *pkt) error {
	pcs := btp.findBridgeablePeers()
	for _, pc := range pcs {
		serverAddr := fmt.Sprintf("%s:%d", pc.PeerProfile.WireguardIP.String(), PeerServiceServerPort)
		c := ConnectPeerServiceClient(serverAddr)
		res, err := c.SetupForwarding(context.Background(), &SetupForwardingRequest{Name: "testing", PeerConnectionType: pc.ConnectionType})
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
			sendTo <- &pkt{message: btp.BindRequestPkt(net.IPv4(res.PublicIP[0], res.PublicIP[1], res.PublicIP[2], res.PublicIP[3]), int(res.PublicPort))}
		}

	}
	return errors.New("Couldn't find a peer to bridge through")
}

func (btp *BindThroughPeer) BindRequestPkt(externalIP net.IP, externalPort int) []byte {
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
