package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func run() {
	setenv("WG_GUI_PID", fmt.Sprintf("%d", os.Getpid()))

	cmd := exec.Command("/usr/bin/open", "-a", "Terminal.app", binPath("wrapper"))
	wireguardCmd = cmd
	runCmd(cmd)
}

func postRun() {
	for {
		fmt.Println("Tunnel was launched. Waiting for the end of this process")
		time.Sleep(1 * time.Minute)
	}
}
