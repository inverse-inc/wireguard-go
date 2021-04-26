package routes

import (
	"fmt"
	"net"
	"os/exec"
)

func Add(ipnet *net.IPNet, gw net.IP, priority int) error {
	res, err := exec.Command("route", "-n", "add", "-net", ipnet.String(), gw.String()).Output()
	if err != nil {
		fmt.Println(string(res))
	}
	return err
}
