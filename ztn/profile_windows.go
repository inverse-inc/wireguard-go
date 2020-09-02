// +build windows

package ztn

import (
	"fmt"
	"os/exec"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
)

func (p *Profile) setupInterface(device *device.Device, WGInterface string) {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address", fmt.Sprintf(`name="%s"`, WGInterface), "static", p.WireguardIP.String(), ipv4MaskString(p.WireguardNetmask))
	fmt.Println(cmd.String())
	err := cmd.Run()
	sharedutils.CheckError(err)
}