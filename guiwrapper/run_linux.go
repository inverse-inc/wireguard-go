package main

import (
	"os"
	"os/exec"
	"path"
)

func run() {
	home := os.Getenv("HOME")
	env := path.Join(home, ".wgenv")

	cmd := exec.Command("pkexec", binPath("wireguard"), env)
	wireguardCmd = cmd
	runCmd(cmd)
}

func elevate() {

}
