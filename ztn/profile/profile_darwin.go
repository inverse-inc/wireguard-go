// +build darwin

package profile

import (
	"os/exec"

	"github.com/inverse-inc/wireguard-go/device"
)

func (p *Profile) setupInterface(device *device.Device, WGInterface string) (error) {
	// ipconfig set utun0 MANUAL 192.168.69.10 255.255.255.0
	cmd := exec.Command("ipconfig", "set", WGInterface, "MANUAL", p.WireguardIP.String(), ipv4MaskString(p.WireguardNetmask))
	err := cmd.Run()
	if err != nil {
		return err
	}
	err = exec.Command("ifconfig", WGInterface, "up").Run()
	if err != nil {
		return err
	}

	return nil
}
