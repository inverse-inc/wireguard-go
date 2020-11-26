package ztn

import (
	"time"

	"github.com/inverse-inc/wireguard-go/device"
)

var PublicPortLivenessTolerance = 10 * time.Minute
var ConnectionLivenessTolerance = device.RekeyTimeout*3 + 1*time.Second

var InboundAttemptsTryAtLeast = 1 * time.Minute
var InboundAttemptsTolerance = 5

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
