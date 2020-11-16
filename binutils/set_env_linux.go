// +build linux

package binutils

import (
	"fmt"
	"os"
	"path"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func init() {
	var err error
	tmp := os.Getenv("HOME")
	Wgenv, err = os.OpenFile(path.Join(tmp, ".wgenv"), os.O_RDWR|os.O_CREATE, 0600)
	sharedutils.CheckError(err)
}

func Setenv(k, v string) {
	_, err := Wgenv.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	sharedutils.CheckError(err)
}
