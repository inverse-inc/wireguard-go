//+build linux darwin

package wgrpc

import (
	"os"

	"github.com/inverse-inc/wireguard-go/util"
)

func stopMasterProcess() {
	p, err := os.FindProcess(os.Getppid())
	if err == nil {
		util.KillProcess(p)
	}
}
