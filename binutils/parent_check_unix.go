// +build darwin linux

package binutils

import "github.com/inverse-inc/wireguard-go/util"

func CheckParentIsAlive(quit func()) {
	util.CheckGUIIsAliveUNIX(quit)
}
