package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/peerrpc"
	"github.com/inverse-inc/wireguard-go/ztn"
)

func main() {
	c := peerrpc.Client()
	res, err := c.SetupForwarding(context.Background(), &peerrpc.SetupForwardingRequest{Name: "testing", PeerConnectionType: ztn.ConnectionTypeLAN})
	sharedutils.CheckError(err)

	spew.Dump(res)

	addr, err := net.ResolveUDPAddr("udp4", res.Raddr)
	sharedutils.CheckError(err)

	time.Sleep(2 * time.Second)

	conn, err := net.DialUDP("udp4", nil, addr)
	sharedutils.CheckError(err)

	pkt := make([]byte, 1024)
	binary.PutUvarint(pkt, res.Id)
	binary.PutUvarint(pkt[binary.MaxVarintLen64:], res.Token)
	binary.PutUvarint(pkt[2*binary.MaxVarintLen64:], ztn.MsgNcBindPeerBridge)

	conn.Write(pkt)

	for {
		buf := make([]byte, 1024)

		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		buf = buf[:n]

		fmt.Printf("Received %s from %s on local addr %s\n", string(buf), raddr, conn.LocalAddr())
	}

}
