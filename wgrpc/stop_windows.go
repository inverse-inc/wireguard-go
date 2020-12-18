package wgrpc

import (
	"fmt"
	"os"
	"syscall"

	godnschange "github.com/inverse-inc/go-dnschange"
	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func stopMasterProcess() {
	c := godnschange.NewDNSChange()
	c.GetDNS()
	c.RestoreDNS("127.0.0.69")
	p, err := os.FindProcess(os.Getppid())
	if err == nil {
		fmt.Println("Killing", p.Pid)
		h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(p.Pid))
		sharedutils.CheckError(err)
		defer syscall.CloseHandle(h)
		err = syscall.TerminateProcess(h, uint32(1))
		sharedutils.CheckError(err)
	}
}