// +build darwin

package ztn

import (
	"fmt"
	"os/exec"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
)

func (p *Profile) setupInterface(device *device.Device, WGInterface string) {
	// ipconfig set utun0 MANUAL 192.168.69.10 255.255.255.0
	cmd := exec.Command("ipconfig", "set", WGInterface, "MANUAL", p.WireguardIP.String(), ipv4MaskString(p.WireguardNetmask))
	fmt.Println(cmd)
	err := cmd.Run()
	sharedutils.CheckError(err)
	err = exec.Command("ifconfig", WGInterface, "up").Run()
	sharedutils.CheckError(err)
}
