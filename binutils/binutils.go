package binutils

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

var wireguardCmd *exec.Cmd

func BinDir() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	sharedutils.CheckError(err)
	return dir
}

func BinPath(name string) string {
	return path.Join(BinDir(), name)
}

func RunCmd(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	sharedutils.CheckError(err)
	cmd.Wait()
}
