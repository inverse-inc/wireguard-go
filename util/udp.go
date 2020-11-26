package util

import (
	"fmt"
	"net"
)

func UDPSend(msg []byte, conn *net.UDPConn, addr *net.UDPAddr) error {
	_, err := conn.WriteToUDP(msg, addr)
	if err != nil {
		return fmt.Errorf("send: %v", err)
	}

	return nil
}

func UDPSendStr(msg string, conn *net.UDPConn, addr *net.UDPAddr) error {
	return UDPSend([]byte(msg), conn, addr)
}
