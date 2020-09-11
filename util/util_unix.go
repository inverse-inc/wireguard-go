//+build linux darwin

package util

import (
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
