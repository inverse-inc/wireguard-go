package binutils

import (
	"os/exec"
)

func run() {
	cmd := exec.Command("/usr/bin/open", "-a", "Terminal.app", binPath("wrapper"))
	wireguardCmd = cmd
	runCmd(cmd)
}
