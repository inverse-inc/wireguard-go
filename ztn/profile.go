package ztn

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os/exec"

	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"golang.zx2c4.com/wireguard/device"
)

type ServerChallenge struct {
	Challenge      string `json:"challenge"`
	PublicKey      string `json:"public_key"`
	BytesChallenge []byte
	BytesPublicKey [32]byte
}

func DoServerChallenge(profile *Profile) string {
	sc, err := GetServerChallenge(profile)
	sharedutils.CheckError(err)

	privateKey, err := remoteclients.B64KeyToBytes(profile.PrivateKey)
	sharedutils.CheckError(err)

	publicKey, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	sharedutils.CheckError(err)

	challenge, err := sc.Decrypt(privateKey)
	sharedutils.CheckError(err)

	challenge = append(challenge, publicKey[:]...)

	challengeEncrypted, err := sc.Encrypt(privateKey, challenge)
	sharedutils.CheckError(err)

	return base64.URLEncoding.EncodeToString(challengeEncrypted)
}

func GetServerChallenge(profile *Profile) (ServerChallenge, error) {
	sc := ServerChallenge{}
	err := GetAPIClient().Call(APIClientCtx, "GET", "/api/v1/remote_clients/server_challenge?public_key="+url.QueryEscape(b64keyToURLb64(profile.PublicKey)), &sc)
	if err != nil {
		return sc, err
	}

	sc.BytesChallenge, err = base64.URLEncoding.DecodeString(sc.Challenge)
	if err != nil {
		return sc, err
	}

	sc.BytesPublicKey, err = remoteclients.URLB64KeyToBytes(sc.PublicKey)
	if err != nil {
		return sc, err
	}

	return sc, nil
}

func (sc *ServerChallenge) Decrypt(privateKey [32]byte) ([]byte, error) {
	sharedSecret := remoteclients.SharedSecret(privateKey, sc.BytesPublicKey)
	return remoteclients.DecryptMessage(sharedSecret[:], sc.BytesChallenge)
}

func (sc *ServerChallenge) Encrypt(privateKey [32]byte, message []byte) ([]byte, error) {
	sharedSecret := remoteclients.SharedSecret(privateKey, sc.BytesPublicKey)
	return remoteclients.EncryptMessage(sharedSecret[:], message)
}

type Profile struct {
	WireguardIP      net.IP   `json:"wireguard_ip"`
	WireguardNetmask int      `json:"wireguard_netmask"`
	PublicKey        string   `json:"public_key"`
	PrivateKey       string   `json:"private_key"`
	AllowedPeers     []string `json:"allowed_peers"`
}

func (p *Profile) SetupWireguard(device *device.Device, WGInterface string) {
	err := exec.Command("ip", "address", "add", "dev", WGInterface, fmt.Sprintf("%s/%d", p.WireguardIP, p.WireguardNetmask)).Run()
	sharedutils.CheckError(err)
	err = exec.Command("ip", "link", "set", "wg0", "up").Run()
	sharedutils.CheckError(err)

	SetConfig(device, "listen_port", fmt.Sprintf("%d", localWGPort))
	SetConfig(device, "private_key", keyToHex(p.PrivateKey))
	SetConfig(device, "persistent_keepalive_interval", "5")
}

func (p *Profile) FillProfileFromServer() {
	auth := DoServerChallenge(p)

	err := GetAPIClient().Call(APIClientCtx, "GET", "/api/v1/remote_clients/profile?public_key="+url.QueryEscape(b64keyToURLb64(p.PublicKey))+"&auth="+url.QueryEscape(auth), &p)
	sharedutils.CheckError(err)
}

type PeerProfile struct {
	WireguardIP net.IP `json:"wireguard_ip"`
	PublicKey   string `json:"public_key"`
}

func GetPeerProfile(id string) (PeerProfile, error) {
	var p PeerProfile
	err := GetAPIClient().Call(APIClientCtx, "GET", "/api/v1/remote_clients/peer/"+id, &p)

	pkey, err := base64.URLEncoding.DecodeString(p.PublicKey)
	sharedutils.CheckError(err)
	p.PublicKey = base64.StdEncoding.EncodeToString(pkey)

	return p, err
}
