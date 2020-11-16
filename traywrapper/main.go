package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/getlantern/systray"
	"github.com/inverse-inc/wireguard-go/binutils"
	"github.com/inverse-inc/wireguard-go/util"
	"github.com/inverse-inc/wireguard-go/util/icon"
)

func setupSystray() {
	setupExitSignals()

	systray.SetIcon(icon.Data)
	//systray.SetTitle(util.AppName)
	systray.SetTooltip(util.AppName)
	mOpen := systray.AddMenuItem("Open", "Open")
	mQuit := systray.AddMenuItem("Quit", "Quit")

	// Sets the icon of a menu item. Only available on Mac and Windows.
	mQuit.SetIcon(icon.Data)

	go func() {
		for {
			select {
			case <-mOpen.ClickedCh:
				go startGUI()
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

func setupExitSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		quit()
	}()
}

func quit() {
	fmt.Println("Tray is exiting")
	if binutils.Wgenv != nil {
		fmt.Println("Cleaning up environment file:", binutils.Wgenv.Name())
		os.Remove(binutils.Wgenv.Name())
	}
	systray.Quit()
	os.Exit(0)
}
