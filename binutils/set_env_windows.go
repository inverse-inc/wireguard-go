// +build windows

package binutils

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func Setenv(k, v string) {
	if Wgenv == nil {
		var err error
		tmp := os.Getenv("TMP")
		Wgenv, err = os.Create(path.Join(tmp, fmt.Sprintf("wgenv-%d", time.Now().Unix())))
		sharedutils.CheckError(err)
	}
	_, err := Wgenv.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	sharedutils.CheckError(err)
}
