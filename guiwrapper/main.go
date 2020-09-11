package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

var wireguardCmd *exec.Cmd
var wgenv *os.File

func main() {
	fmt.Println("Starting up")
	setenv("WG_GUI_PID", fmt.Sprintf("%d", os.Getpid()))
	setenv("WG_GUI_WINDOWS_PROCESS_NAME", "guiwrapper.exe")

	go startTray()
	setupExitSignals()
	SetupAPIClientGUI(func() {
		run()
		postRun()
		quit()
	})
	quit()
}

func startTray() {
	cmd := exec.Command(binPath("traywrapper"))
	runCmd(cmd)
	fmt.Println("Tray has exited, exiting")
	quit()
}

func quit() {
	if wgenv != nil {
		fmt.Println("Cleaning up environment file:", wgenv.Name())
		os.Remove(wgenv.Name())
	}
	os.Exit(0)
}

func setupExitSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		quit()
	}()
}
