//+build linux darwin

package util

import (
	"fmt"
	"os"
	"syscall"
)

func CheckPIDIsAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil || pid == 1 {
		return false
	} else if err := process.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	return true
}

func KillProcess(p *os.Process) {
	fmt.Println("Killing", p.Pid)
	p.Signal(syscall.SIGTERM)
}
