package main

import (
	"fmt"
	"os/exec"
	"time"
)

func run() {
	cmd := exec.Command("/usr/bin/open", "-a", "Terminal.app", binPath("wrapper"))
	wireguardCmd = cmd
	runCmd(cmd)
}

func postRun() {
	fmt.Println("Tunnel was launched. Waiting for the end of this process")
	for {
		//TODO: receive a signal from the tunnel that it has exited
		time.Sleep(1 * time.Second)
	}
}
