package main

import (
	"os"
	"os/exec"
)

func run() {
	cmd := exec.Command("C:\\Program Files\\Wireguard\\run.bat")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}
