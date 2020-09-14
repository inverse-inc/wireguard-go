// +build windows

package profile

import (
	"fmt"
	"os/exec"

	"github.com/inverse-inc/wireguard-go/device"
)

func (p *Profile) setupInterface(device *device.Device, WGInterface string) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address", fmt.Sprintf(`name="%s"`, WGInterface), "static", p.WireguardIP.String(), ipv4MaskString(p.WireguardNetmask))
	err := cmd.Run()
	return err
}
