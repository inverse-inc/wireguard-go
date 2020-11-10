package routes

import (
	"fmt"
	"net"
	"os/exec"
	"time"
)

func Add(ipnet *net.IPNet, gw net.IP) error {
	go func() {
		// Sleep to give time to the WG interface to get up
		time.Sleep(5 * time.Second)
		res, err := exec.Command("route", "add", ipnet.IP.String(), "mask", net.IPv4(ipnet.Mask[0], ipnet.Mask[1], ipnet.Mask[2], ipnet.Mask[3]).String(), gw.String()).Output()
		if err != nil {
			fmt.Println(string(res))
		}
	}()
	return nil
}
