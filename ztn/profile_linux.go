// +build linux

package ztn

import (
	"errors"
	"fmt"
	"net"
	"os/exec"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/jackpal/gateway"
)

func (p *Profile) setupInterface(device *device.Device, WGInterface string) {
	err := exec.Command("ip", "address", "add", "dev", WGInterface, fmt.Sprintf("%s/%d", p.WireguardIP, p.WireguardNetmask)).Run()
	sharedutils.CheckError(err)
	err = exec.Command("ip", "link", "set", WGInterface, "up").Run()
	sharedutils.CheckError(err)
}

func (p *Profile) findClientMAC() (net.HardwareAddr, error) {
	gwIP, err := gateway.DiscoverGateway()
	sharedutils.CheckError(err)

	p.logger.Debug.Println("Found default gateway", gwIP)

	ifaces, err := net.Interfaces()
	sharedutils.CheckError(err)

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			p.logger.Error.Printf("Unable to get IP address for interface: %v\n", err.Error())
			continue
		}
		for _, a := range addrs {
			switch ipnet := a.(type) {
			case *net.IPNet:
				if ipnet.Contains(gwIP) {
					p.logger.Info.Println("Found MAC address", i.HardwareAddr, "on interface", ipnet, "("+i.Name+")")
					return i.HardwareAddr, nil
				}
			}
		}
	}

	return net.HardwareAddr{}, errors.New("Unable to find MAC address")
}
