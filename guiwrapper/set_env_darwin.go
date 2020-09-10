// +build darwin

package main

import (
	"fmt"
	"os"
	"path"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

var wgenv *os.File

func init() {
	var err error
	tmp := os.Getenv("HOME")
	wgenv, err = os.OpenFile(path.Join(tmp, ".wgenv"), os.O_RDWR|os.O_CREATE, 0600)
	sharedutils.CheckError(err)
}

func setenv(k, v string) {
	_, err := wgenv.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	sharedutils.CheckError(err)
}
