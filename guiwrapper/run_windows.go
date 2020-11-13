package main

import (
	"fmt"
	"os"
	"os/exec"
)

func run() {

	cmd := exec.Command("C:\\Program Files\\PacketFence-Zero-Trust-Client\\run.bat", wgenv.Name())
	fmt.Println(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}
