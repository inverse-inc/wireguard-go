package binutils

import (
	"os"
	"os/exec"
	"path"
)

func RunTunnel() {
	home := os.Getenv("HOME")
	env := path.Join(home, ".wgenv")

	cmd := exec.Command("pkexec", BinPath("wireguard"), env, "--master")
	wireguardCmd = cmd
	RunCmd(cmd)
}

func Elevate() {

}
