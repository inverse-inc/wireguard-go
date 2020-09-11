package main

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func binDir() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	sharedutils.CheckError(err)
	return dir
}

func binPath(name string) string {
	return path.Join(binDir(), name)
}

func runCmd(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	sharedutils.CheckError(err)
	cmd.Wait()
}
