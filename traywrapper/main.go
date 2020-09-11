package main

import (
	"fmt"
	"os"

	"github.com/getlantern/systray"
	"github.com/getlantern/systray/example/icon"
	"github.com/joho/godotenv"
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
		if len(os.Args) > 1 {
			godotenv.Load(os.Args[1])
		}
		go checkParentIsAlive()
	}, func() {})
}

func quit() {
	fmt.Println("Tray is exiting")
	systray.Quit()
	os.Exit(0)
}
