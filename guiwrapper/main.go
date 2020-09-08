package main

import (
	"bufio"
	"fmt"
	"os/exec"

	"github.com/getlantern/systray"
	"github.com/getlantern/systray/example/icon"
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
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()

		scanner := bufio.NewScanner(stdout)
		scanner.Split(bufio.ScanWords)
		for scanner.Scan() {
			m := scanner.Text()
			fmt.Println(m)
		}

		cmd.Wait()

	}, func() {})
}
