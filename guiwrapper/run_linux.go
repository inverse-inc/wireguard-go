package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func run() {
	cmd := exec.Command("sudo", "echo", "Granted root access")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to obtain root access")
		os.Exit(1)
	}

	cmd = exec.Command("sudo", "-E", "../wireguard-go", "-f", "wg0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}

func postRun() {}
