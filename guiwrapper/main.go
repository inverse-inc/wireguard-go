package main

import (
	"fmt"
	"os/exec"

	"github.com/getlantern/systray"
	"github.com/getlantern/systray/example/icon"
	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func main() {
	systray.Run(func() {
		systray.SetIcon(icon.Data)
		systray.SetTitle("Awesome App")
		systray.SetTooltip("Pretty awesome")
		mQuit := systray.AddMenuItem("Quit", "Quit the whole app")

		// Sets the icon of a menu item. Only available on Mac and Windows.
		mQuit.SetIcon(icon.Data)

		cmd := exec.Command("sudo", "../wireguard-go", "-f", "wg0")
		out, err := cmd.Output()
		fmt.Println(string(out))
		sharedutils.CheckError(err)
	}, func() {})
}
