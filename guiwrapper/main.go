package main

import (
	"fmt"
	"os"
	"os/exec"
)

var wireguardCmd *exec.Cmd

func main() {
	fmt.Println("Starting up")
	go startTray()
	SetupAPIClientGUI(func() {
		run()
		postRun()
		quit()
	})
}

func startTray() {
	cmd := exec.Command(binPath("traywrapper"))
	runCmd(cmd)
	fmt.Println("Tray has exited, exiting")
	os.Exit(0)
}

func quit() {
	os.Exit(0)
}
