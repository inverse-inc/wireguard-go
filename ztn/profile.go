package ztn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	sc, err := getServerChallenge(profile)
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

func getServerChallenge(profile *Profile) (ServerChallenge, error) {
	sc := ServerChallenge{}
	res, err := http.Get(orchestrationServer + "/server_challenge?public_key=" + url.QueryEscape(b64keyToURLb64(profile.PublicKey)))
	if err != nil {
		return sc, err
	}

	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return sc, errors.New("Failed to get server challenge, got status: " + res.Status)
	}

	err = json.NewDecoder(res.Body).Decode(&sc)
	if err != nil {
		return sc, err
	}

	sc.BytesChallenge, err = base64.URLEncoding.DecodeString(sc.Challenge)
	if err != nil {
		return sc, err
	}

	sc.BytesPublicKey, err = remoteclients.URLB64KeyToBytes(sc.PublicKey)

	return sc, err
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

func (p *Profile) SetupWireguard(device *device.Device) {
	err := exec.Command("ip", "address", "add", "dev", "wg0", fmt.Sprintf("%s/%d", p.WireguardIP, p.WireguardNetmask)).Run()
	sharedutils.CheckError(err)
	err = exec.Command("ip", "link", "set", "wg0", "up").Run()
	sharedutils.CheckError(err)

	SetConfig(device, "listen_port", "6969")
	SetConfig(device, "private_key", keyToHex(p.PrivateKey))
}

func (p *Profile) FillProfileFromServer() {
	auth := DoServerChallenge(p)

	res, err := http.Get(orchestrationServer + "/profile?public_key=" + url.QueryEscape(b64keyToURLb64(p.PublicKey)) + "&auth=" + url.QueryEscape(auth))
	sharedutils.CheckError(err)

	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		panic(errors.New("Failed to get profile, got status: " + res.Status))
	}

	err = json.NewDecoder(res.Body).Decode(&p)

	sharedutils.CheckError(err)
}

type PeerProfile struct {
	WireguardIP net.IP `json:"wireguard_ip"`
	PublicKey   string `json:"public_key"`
}

func GetPeerProfile(id string) (PeerProfile, error) {
	var p PeerProfile
	res, err := http.Get(orchestrationServer + "/peer/" + id)
	if err != nil {
		return p, err
	}
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&p)

	pkey, err := base64.URLEncoding.DecodeString(p.PublicKey)
	sharedutils.CheckError(err)
	p.PublicKey = base64.StdEncoding.EncodeToString(pkey)

	return p, err
}
