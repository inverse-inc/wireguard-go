package routes

import (
	"fmt"
	"net"
	"os/exec"
)

func Add(ipnet *net.IPNet, gw net.IP, priority int) error {
	res, err := exec.Command(
		"route", "add", 
		ipnet.IP.String(), "mask", net.IPv4(ipnet.Mask[0], ipnet.Mask[1], ipnet.Mask[2], ipnet.Mask[3]).String(), gw.String(),
		"metric", fmt.Sprintf("%d", priority),
	).Output()
	if err != nil {
		fmt.Println(string(res))
	}
	return err
}
