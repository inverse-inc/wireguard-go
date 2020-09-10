package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func run() {
	setenv("WG_GUI_PID", fmt.Sprintf("%d", os.Getpid()))
	setenv("WG_GUI_PROCESS_NAME", "guiwrapper.exe")

	cmd := exec.Command("C:\\Program Files\\Wireguard\\run.bat", wgenv.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}

func postRun() {
	for {
		fmt.Println("Tunnel was launched. Waiting for the end of this process")
		time.Sleep(1 * time.Minute)
	}
}