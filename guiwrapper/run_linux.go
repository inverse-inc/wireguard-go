package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func run() {
	setenv("WG_GUI_PID", fmt.Sprintf("%d", os.Getpid()))

	cmd := exec.Command("sudo", "echo", "Granted root access")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to obtain root access")
		os.Exit(1)
	}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	sharedutils.CheckError(err)

	cmd = exec.Command("sudo", "-E", dir+"/wireguard", "-f", "wg0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}

func postRun() {}
