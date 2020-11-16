package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/getlantern/systray"
	"github.com/inverse-inc/wireguard-go/binutils"
	"github.com/inverse-inc/wireguard-go/util"
	"github.com/inverse-inc/wireguard-go/util/icon"
)

func setupSystray() {
	systray.SetIcon(icon.Data)
	//systray.SetTitle(util.AppName)
	systray.SetTooltip(util.AppName)
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
		fmt.Println("Starting up")
		binutils.Setenv("WG_GUI_PID", fmt.Sprintf("%d", os.Getpid()))

		binutils.Elevate()
		go startGUI()

		setupSystray()
	}, func() {})
}

func startGUI() {
	var cmd *exec.Cmd
	if binutils.Wgenv != nil {
		cmd = exec.Command(binutils.BinPath("guiwrapper"), binutils.Wgenv.Name())
	} else {
		cmd = exec.Command(binutils.BinPath("guiwrapper"))
	}
	binutils.RunCmd(cmd)
}

func quit() {
	fmt.Println("Tray is exiting")
	systray.Quit()
	os.Exit(0)
}
