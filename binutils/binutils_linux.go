package binutils

import (
	"os/exec"
)

func RunTunnel() {
	cmd := exec.Command("pkexec", BinPath("wireguard"), Wgenv.Name(), "--master")
	wireguardCmd = cmd
	RunCmd(cmd)
}

func Elevate() {

}
