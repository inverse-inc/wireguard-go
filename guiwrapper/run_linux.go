package main

import (
	"fmt"
	"os"
	"os/exec"
)

func run() {
	cmd := exec.Command("sudo", "echo", "Granted root access")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to obtain root access")
		os.Exit(1)
	}

	cmd = exec.Command("sudo", "-E", binPath("wireguard"), "-f", "wg0")
	wireguardCmd = cmd
	runCmd(cmd)
}
