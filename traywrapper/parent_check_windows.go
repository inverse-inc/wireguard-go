// +build windows

package main

import "github.com/inverse-inc/wireguard-go/util"

func checkParentIsAlive() {
	util.CheckGUIIsAliveWindows(quit)
}
