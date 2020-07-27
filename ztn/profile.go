package ztn

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"golang.zx2c4.com/wireguard/device"
)

type Profile struct {
	WireguardIP      net.IP   `json:"wireguard_ip"`
	WireguardNetmask int      `json:"wireguard_netmask"`
	PublicKey        string   `json:"public_key"`
	PrivateKey       string   `json:"private_key"`
	AllowedPeers     []string `json:"allowed_peers"`
}

func (p *Profile) SetupWireguard(device *device.Device) {
	err := exec.Command("ip", "address", "add", "dev", "wg0", fmt.Sprintf("%s/%d", p.WireguardIP, p.WireguardNetmask)).Run()
	sharedutils.CheckError(err)
	err = exec.Command("ip", "link", "set", "wg0", "up").Run()
	sharedutils.CheckError(err)

	SetConfig(device, "listen_port", "6969")
	SetConfig(device, "private_key", keyToHex(p.PrivateKey))
}

type PeerProfile struct {
	WireguardIP net.IP `json:"wireguard_ip"`
	PublicKey   string `json:"public_key"`
}

func GetProfile(id string) (Profile, error) {
	var p Profile
	res, err := http.Get(orchestrationServer + "/profile/" + id)
	if err != nil {
		return p, err
	}
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&p)
	return p, err
}

func GetPeerProfile(id string) (PeerProfile, error) {
	var p PeerProfile
	res, err := http.Get(orchestrationServer + "/peer/" + id)
	if err != nil {
		return p, err
	}
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&p)
	return p, err
}
