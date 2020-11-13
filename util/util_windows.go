//+build windows

package util

import (
	"os/exec"
	"fmt"
	"regexp"
	"strings"
	"syscall"
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