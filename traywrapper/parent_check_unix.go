// +build darwin linux

package main

import "github.com/inverse-inc/wireguard-go/util"

func checkParentIsAlive() {
	util.CheckGUIIsAliveUNIX(quit)
}
