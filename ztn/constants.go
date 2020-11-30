package ztn

import (
	"time"

	"github.com/inverse-inc/wireguard-go/device"
)

var PublicPortLivenessTolerance = 10 * time.Minute
var ConnectionLivenessTolerance = device.RekeyTimeout * 2

var InboundAttemptsTryAtLeast = 30 * time.Second
var InboundAttemptsTolerance = 2

const udp = "udp"
const pingMsg = "ping"

const stunServer = "srv.semaan.ca:3478"

const (
	MsgNcBindPeerBridge = uint64(1)
)

const (
	ConnectionTypeLAN     = "LAN"
	ConnectionTypeWANIN   = "WAN IN"
	ConnectionTypeWANOUT  = "WAN OUT"
	ConnectionTypeWANSTUN = "WAN STUN"
)

func PublicPortTTL() int {
	// 30 days
	return 30 * 24 * 60 * 60
}
