package constants

import "net"

var LocalWGIP = net.ParseIP("127.0.0.1")

const LocalWGPort = 6969

const LowerPort = 1025

const HigherPort = 65535
