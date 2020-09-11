package main

import (
	"fmt"
	"os"

	"github.com/getlantern/systray"
	"github.com/getlantern/systray/example/icon"
)

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
		setupSystray()
		go checkParentIsAlive()
	}, func() {})
}

func quit() {
	fmt.Println("Tray is exiting")
	systray.Quit()
	os.Exit(0)
}
