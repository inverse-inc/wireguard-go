// +build linux

package ztn

import (
	"fmt"
	"os/exec"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
)

func (p *Profile) setupInterface(device *device.Device, WGInterface string) {
	err := exec.Command("ip", "address", "add", "dev", WGInterface, fmt.Sprintf("%s/%d", p.WireguardIP, p.WireguardNetmask)).Run()
	sharedutils.CheckError(err)
	err = exec.Command("ip", "link", "set", "wg0", "up").Run()
	sharedutils.CheckError(err)
}
