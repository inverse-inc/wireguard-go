package binutils

import (
	"os/exec"
	"time"
)

func RunTunnel() {
	cmd := exec.Command("/usr/bin/osascript", "-e", `do shell script "'`+BinPath("wireguard-go")+`' `+Wgenv.Name()+` & sleep 10" with administrator privileges`)
	wireguardCmd = cmd
	go RunCmd(cmd)
	time.Sleep(10 * time.Second)
	cmd.Process.Kill()
}

func Elevate() {

}
