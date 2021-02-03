//+build windows

package util

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func CheckPIDIsAlive(pid int) bool {
	cmd := exec.Command("tasklist")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Unable to run tasklist: ", err, string(output))
	}
	re := regexp.MustCompile(fmt.Sprintf(`^\S+\s+%d\s+`, pid))
	lines := strings.Split(string(output), "\n")
	for _, l := range lines {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

func KillProcess(p *os.Process) {
	fmt.Println("Killing", p.Pid)
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(p.Pid))
	sharedutils.CheckError(err)
	defer syscall.CloseHandle(h)
	err = syscall.TerminateProcess(h, uint32(1))
	sharedutils.CheckError(err)
}
