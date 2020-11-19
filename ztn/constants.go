package ztn

import (
	"time"
)

var PublicPortLivenessTolerance = 10 * time.Minute
var ConnectionLivenessTolerance = 10 * time.Second

var InboundAttemptsTryAtLeast = 1 * time.Minute
var InboundAttemptsTolerance = 5

const udp = "udp"
const pingMsg = "ping"

const stunServer = "srv.semaan.ca:3478"

func PublicPortTTL() int {
	return int(PublicPortLivenessTolerance/time.Second) * 2
}
