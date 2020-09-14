// +build linux

package ztn

import (
	"fmt"
	"os/exec"

	"github.com/inverse-inc/wireguard-go/device"
)

func (p *Profile) setupInterface(device *device.Device, WGInterface string) error {
	err := exec.Command("ip", "address", "add", "dev", WGInterface, fmt.Sprintf("%s/%d", p.WireguardIP, p.WireguardNetmask)).Run()
	if err != nil {
		return err
	}
	err = exec.Command("ip", "link", "set", WGInterface, "up").Run()
	if err != nil {
		return err
	}

	return nil
}
