package profile

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/wgrpc"
	"github.com/inverse-inc/wireguard-go/ztn/api"
	"github.com/inverse-inc/wireguard-go/ztn/config"
	"github.com/inverse-inc/wireguard-go/ztn/constants"
	"github.com/inverse-inc/wireguard-go/ztn/rpc"
	"github.com/inverse-inc/wireguard-go/ztn/util"
	"github.com/jackpal/gateway"
)

type ServerChallenge struct {
	Challenge      string `json:"challenge"`
	PublicKey      string `json:"public_key"`
	BytesChallenge []byte
	BytesPublicKey [32]byte
}

func (p *Profile) DoServerChallenge(profile *Profile) (string, error) {
	sc, err := p.GetServerChallenge(profile)
	if err != nil {
		return "", err
	}

	privateKey, err := remoteclients.B64KeyToBytes(profile.PrivateKey)
	if err != nil {
		return "", err
	}

	publicKey, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	if err != nil {
		return "", err
	}

	challenge, err := sc.Decrypt(privateKey)
	if err != nil {
		return "", err
	}

	challenge = append(challenge, publicKey[:]...)

	challengeEncrypted, err := sc.Encrypt(privateKey, challenge)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(challengeEncrypted), nil
}

func (p *Profile) GetServerChallenge(profile *Profile) (ServerChallenge, error) {
	sc := ServerChallenge{}
	err := api.GetAPIClient().Call(api.APIClientCtx, "GET", "/api/v1/remote_clients/server_challenge?public_key="+url.QueryEscape(util.B64keyToURLb64(profile.PublicKey)), &sc)
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
	logger           *device.Logger
}

func (p *Profile) SetupWireguard(device *device.Device, WGInterface string) error {
	err := p.setupInterface(device, WGInterface)
	if err != nil {
		return err
	}

	config.SetConfig(device, "listen_port", fmt.Sprintf("%d", constants.LocalWGPort))
	config.SetConfig(device, "private_key", util.KeyToHex(p.PrivateKey))

	rpc.WGRPCServer.UpdateStatus(wgrpc.STATUS_CONNECTED, nil)
	return nil
}

func (p *Profile) FillProfileFromServer(logger *device.Logger) error {
	p.logger = logger

	auth, err := p.DoServerChallenge(p)
	if err != nil {
		return err
	}

	mac, _, err := p.FindClientMAC()
	if err != nil {
		return err
	}

	err = api.GetAPIClient().Call(api.APIClientCtx, "GET", "/api/v1/remote_clients/profile?public_key="+url.QueryEscape(util.B64keyToURLb64(p.PublicKey))+"&auth="+url.QueryEscape(auth)+"&mac="+url.QueryEscape(mac.String()), &p)

	if err != nil {
		return err
	} else {
		return nil
	}
}

func (p *Profile) FindClientMAC() (net.HardwareAddr, net.IPNet, error) {
	gwIP, err := gateway.DiscoverGateway()
	if err != nil {
		return net.HardwareAddr{}, net.IPNet{}, err
	}

	p.logger.Debug.Println("Found default gateway", gwIP)

	ifaces, err := net.Interfaces()
	if err != nil {
		return net.HardwareAddr{}, net.IPNet{}, err
	}

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
					return i.HardwareAddr, *ipnet, nil
				}
			}
		}
	}

	return net.HardwareAddr{}, net.IPNet{}, errors.New("Unable to find MAC address")
}

type PeerProfile struct {
	WireguardIP net.IP `json:"wireguard_ip"`
	PublicKey   string `json:"public_key"`
}

func (p *Profile) GetPeerProfile(id string) (PeerProfile, error) {
	var peer PeerProfile
	err := api.GetAPIClient().Call(api.APIClientCtx, "GET", "/api/v1/remote_clients/peer/"+id, &peer)

	pkey, err := base64.URLEncoding.DecodeString(peer.PublicKey)
	sharedutils.CheckError(err)
	peer.PublicKey = base64.StdEncoding.EncodeToString(pkey)
	return peer, err
}
