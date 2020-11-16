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

const (
	STATUS_CONNECTED = "CONNECTED"
	STATUS_ERROR     = "ERROR"
	STATUS_NOT_READY = ""

	PEER_STATUS_CONNECTED             = "Connected"
	PEER_STATUS_INITIATING_CONNECTION = "Waiting for peer to register"
	PEER_STATUS_CONNECT_PRIVATE       = "Attempting to connect to peer via local area network"
	PEER_STATUS_CONNECT_PUBLIC        = "Attempting to connect to peer via the Internet"
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

func ipv4MaskString(mask int) string {
	_, ipv4Net, err := net.ParseCIDR(fmt.Sprintf("0.0.0.0/%d", mask))
	if err != nil {
		panic(err)
	}

	m := ipv4Net.Mask

	if len(m) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

func RunningInCLI() bool {
	return sharedutils.EnvOrDefault("WG_CLI", "true") == "true"
}

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
