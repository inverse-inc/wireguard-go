package ztn

import (
	"errors"
	"net"
	"os"
	"sync"
)

type PublicPort struct {
	sync.Mutex
	BindTechniqueBase
	remoteIP   net.IP
	remotePort int
}

func NewPublicPort() *PublicPort {
	pp := &PublicPort{}
	pp.InitID()
	return pp
}

func (pp *PublicPort) BindRequest(conn *net.UDPConn, sendTo chan *pkt) error {
	pp.Lock()
	defer pp.Unlock()

	if pp.remotePort != 0 {
		return nil
	}

	pp.remoteIP = net.ParseIP(os.Getenv(EnvPublicPortIP))
	if pp.remoteIP == nil {
		return errors.New(EnvPublicPortIP + " is not defined in the environment or is not a valid IPv4 address")
	}
	pp.remotePort = localWGPort

	go func() {
		sendTo <- &pkt{message: pp.BindRequestPkt(pp.remoteIP, pp.remotePort)}
	}()
	return nil
}
