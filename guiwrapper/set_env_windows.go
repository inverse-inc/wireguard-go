// +build windows

package main

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func setenv(k, v string) {
	if wgenv == nil {
		var err error
		tmp := os.Getenv("TMP")
		wgenv, err = os.Create(path.Join(tmp, fmt.Sprintf("wgenv-%d", time.Now().Unix())))
		sharedutils.CheckError(err)
	}
	_, err := wgenv.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	sharedutils.CheckError(err)
}
