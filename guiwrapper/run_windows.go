package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func run() {

	cmd := exec.Command("C:\\Program Files\\Wireguard\\run.bat", wgenv.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}

func postRun() {
	fmt.Println("Tunnel was launched. Waiting for the end of this process")
	for {
		time.Sleep(1 * time.Minute)
	}
}
