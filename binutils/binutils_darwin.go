package binutils

import (
	"os/exec"
)

func RunTunnel() {
	cmd := exec.Command("/usr/bin/osascript", "-e", `do shell script "'`+BinPath("wireguard-go")+`' `+Wgenv.Name()+` 2>&1 etc" with administrator privileges`)
	wireguardCmd = cmd
	RunCmd(cmd)
}

func Elevate() {

}
