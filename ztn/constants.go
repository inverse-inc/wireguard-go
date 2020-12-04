package ztn

import (
	"time"

	"github.com/inverse-inc/wireguard-go/device"
)

var PublicPortLivenessTolerance = 10 * time.Minute
var InitialConnectionLivenessTolerance = device.RekeyTimeout * 2
var ConnectedConnectionLivenessTolerance = 10 * time.Second

var InboundAttemptsTryAtLeast = 20 * time.Second
var InboundAttemptsTolerance = 2

const udp = "udp"
const pingMsg = "ping"

var stunServer = ""

const (
	MsgNcBindPeerBridge = uint64(1)
)

const (
	ConnectionTypeLANIN   = "LAN IN"
	ConnectionTypeLANOUT  = "LAN OUT"
	ConnectionTypeWANIN   = "WAN IN"
	ConnectionTypeWANOUT  = "WAN OUT"
	ConnectionTypeWANSTUN = "WAN STUN"
)

var EnvGUIPID = ""
var EnvCLI = ""
var EnvServer = ""
var EnvServerPort = ""
var EnvServerVerifyTLS = ""
var EnvUsername = ""
var EnvHonorRoutes = ""
var EnvBindTechnique = ""
var EnvPassword = ""
var EnvCLIInterractive = ""
var EnvOffersBridging = ""
var EnvMaxPeerBridges = ""
var EnvGatewayOutboundInterface = ""

func PublicPortTTL() int {
	// 30 days
	return 30 * 24 * 60 * 60
}
