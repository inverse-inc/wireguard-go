package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/getlantern/systray"
	"github.com/getlantern/systray/example/icon"
)

var wireguardCmd *exec.Cmd

func setupSystray() {
	systray.SetIcon(icon.Data)
	systray.SetTitle("Wireguard client")
	systray.SetTooltip("Wireguard client")
	mQuit := systray.AddMenuItem("Quit", "Quit")

	// Sets the icon of a menu item. Only available on Mac and Windows.
	mQuit.SetIcon(icon.Data)

	go func() {
		for {
			select {
			case <-mQuit.ClickedCh:
				quit()
			}
		}
	}()
}

func main() {
	systray.Run(func() {
		fmt.Println("Launching GUI wrapper")
		setupSystray()
		run()
		quit()
	}, func() {})
}

func quit() {
	systray.Quit()
	os.Exit(0)
}
