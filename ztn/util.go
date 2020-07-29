package ztn

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"gortc.io/stun"
)

func udpSend(msg []byte, conn *net.UDPConn, addr *net.UDPAddr) error {
	_, err := conn.WriteToUDP(msg, addr)
	if err != nil {
		return fmt.Errorf("send: %v", err)
	}

	return nil
}

func udpSendStr(msg string, conn *net.UDPConn, addr *net.UDPAddr) error {
	return udpSend([]byte(msg), conn, addr)
}

func keyToHex(b64 string) string {
	data, err := base64.StdEncoding.DecodeString(b64)
	sharedutils.CheckError(err)
	return hex.EncodeToString(data)
}

func sendBindingRequest(conn *net.UDPConn, addr *net.UDPAddr) error {
	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	err := udpSend(m.Raw, conn, addr)
	if err != nil {
		return fmt.Errorf("binding: %v", err)
	}

	return nil
}

func b64keyToURLb64(k string) string {
	b, err := remoteclients.B64KeyToBytes(k)
	sharedutils.CheckError(err)
	return base64.URLEncoding.EncodeToString(b[:])
}
