package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func run() {
	setenv("WG_GUI_PID", fmt.Sprintf("%d", os.Getpid()))

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	sharedutils.CheckError(err)

	cmd := exec.Command("/usr/bin/open", "-a", "Terminal.app", dir+"/wrapper")
	err = cmd.Run()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}

func postRun() {
	for {
		fmt.Println("Tunnel was launched. Waiting for the end of this process")
		time.Sleep(1 * time.Minute)
	}
}
