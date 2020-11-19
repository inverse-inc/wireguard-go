package ztn

import "time"

const (
	BindSTUN    = BindTechnique("STUN")
	BindUPNPGID = BindTechnique("UPNPGID")
	BindNATPMP  = BindTechnique("NATPMP")
)

var DefaultBindTechnique = BindSTUN

var PublicPortTTL = 10 * time.Minute
var ConnectionLivenessTolerance = 10 * time.Second

const udp = "udp"
const pingMsg = "ping"

const stunServer = "srv.semaan.ca:3478"
