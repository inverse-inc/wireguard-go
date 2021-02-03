package wgrpc

import (
	"os"

	godnschange "github.com/inverse-inc/go-dnschange"
	"github.com/inverse-inc/wireguard-go/util"
)

func stopMasterProcess() {
	c := godnschange.NewDNSChange()
	c.GetDNS()
	c.RestoreDNS("127.0.0.69")
	p, err := os.FindProcess(os.Getppid())
	if err == nil {
		util.KillProcess(p)
	}
}
