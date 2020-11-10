package routes

import (
	"fmt"
	"net"
	"os/exec"
)

func Add(ipnet *net.IPNet, gw net.IP) error {
	res, err := exec.Command("ip", "route", "add", ipnet.String(), "via", gw.String()).Output()
	if err != nil {
		fmt.Println(string(res))
	}
	return err
}
