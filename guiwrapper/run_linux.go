package main

import (
	"os"
	"os/exec"
	"syscall"
)

func run() {
	cmd := exec.Command("sudo", "-E", "../wireguard-go", "-f", "wg0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}
