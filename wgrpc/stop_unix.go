//+build linux darwin

package wgrpc

import (
	"fmt"
	"os"
	"syscall"
)

func stopMasterProcess() {
	p, err := os.FindProcess(os.Getppid())
    if err == nil {
      fmt.Println("Killing", p.Pid)
      p.Signal(syscall.SIGTERM)
    }
}