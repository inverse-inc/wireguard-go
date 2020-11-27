package ztn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/routes"
	"github.com/jackpal/gateway"
)

type ServerChallenge struct {
	Challenge      string `json:"challenge"`
	PublicKey      string `json:"public_key"`
	BytesChallenge []byte
	BytesPublicKey [32]byte
}

func DoServerChallenge(profile *Profile) (string, error) {
	sc, err := GetServerChallenge(profile)
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

func GetServerChallenge(profile *Profile) (ServerChallenge, error) {
	sc := ServerChallenge{}
	var err error
	err = GetAPIClient().Call(APIClientCtx, "GET", "/api/v1/remote_clients/server_challenge?public_key="+url.QueryEscape(b64keyToURLb64(profile.PublicKey)), &sc)
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
	remoteclients.Peer
	PrivateKey string `json:"private_key"`
	logger     *device.Logger
	connection *Connection
}

func (p *Profile) SetupWireguard(device *device.Device, WGInterface string) error {
	err := p.setupInterface(device, WGInterface)
	if err != nil {
		return err
	}

	SetConfig(device, "listen_port", fmt.Sprintf("%d", localWGPort))
	SetConfig(device, "private_key", keyToHex(p.PrivateKey))

	p.connection.Update(func() {
		p.connection.Status = STATUS_CONNECTED
		p.connection.LastError = nil
	})

	if p.IsGateway {
		err = p.SetupGateway()
		if err != nil {
			return err
		}
	} else {
		err = p.SetupRoutes()
		if err != nil {
			return err
		}
	}

	go StartPeerServiceRPC(p.WireguardIP, p.logger)

	return nil
}

func (p *Profile) FillProfileFromServer(connection *Connection, logger *device.Logger) error {
	p.logger = logger
	p.connection = connection

	auth, err := DoServerChallenge(p)
	if err != nil {
		return err
	}

	mac, err := p.findClientMAC()
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	err = GetAPIClient().Call(
		APIClientCtx,
		"GET",
		"/api/v1/remote_clients/profile?public_key="+
			url.QueryEscape(b64keyToURLb64(p.PublicKey))+
			"&auth="+url.QueryEscape(auth)+
			"&mac="+url.QueryEscape(mac.String())+
			"&hostname="+url.QueryEscape(hostname),
		&p,
	)

	if err != nil {
		return err
	} else {
		return nil
	}
}

func (p *Profile) findClientMAC() (net.HardwareAddr, error) {
	gwIP, err := gateway.DiscoverGateway()
	if err != nil {
		return net.HardwareAddr{}, err
	}

	p.logger.Debug.Println("Found default gateway", gwIP)

	ifaces, err := net.Interfaces()
	if err != nil {
		return net.HardwareAddr{}, err
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
					return i.HardwareAddr, nil
				}
			}
		}
	}

	return net.HardwareAddr{}, errors.New("Unable to find MAC address")
}

type RouteInfo struct {
	Network *net.IPNet
	Gateway net.IP
}

var routesRegexp = regexp.MustCompile(`([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}) via ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`)

func (p *Profile) ParseRoutes() []RouteInfo {
	info := []RouteInfo{}
	for _, routeRaw := range p.Routes {
		ri := RouteInfo{}
		var err error
		if match := routesRegexp.FindAllStringSubmatch(routeRaw, 2); len(match) == 1 && len(match[0]) == 3 {
			_, ri.Network, err = net.ParseCIDR(match[0][1])
			if err != nil {
				p.logger.Error.Printf("Invalid network CIDR %s in line %s", match[0][1], routeRaw)
				continue
			}
			ri.Gateway = net.ParseIP(match[0][2])
			if ri.Gateway == nil {
				p.logger.Error.Printf("Invalid gateway IP %s in line %s", match[0][2], routeRaw)
				continue
			}
			info = append(info, ri)
		} else {
			p.logger.Error.Printf("Ignoring route %s because it doesn't match the known format", routeRaw)
		}
	}
	return info
}

func (p *Profile) SetupRoutes() error {
	if sharedutils.EnvOrDefault("WG_HONOR_ROUTES", "true") == "true" {
		for _, r := range p.ParseRoutes() {
			p.logger.Info.Println("Installing route to", r.Network, "via", r.Gateway)
			go func(r RouteInfo) {
				// Sleep to give time to the WG interface to get up
				time.Sleep(5 * time.Second)
				err := routes.Add(r.Network, r.Gateway)
				if err != nil {
					p.logger.Error.Println("Error while nstalling route to", r.Network, "via", r.Gateway, ":", err)
				}
			}(r)
		}
	} else {
		p.logger.Info.Println("Not installing routes as the configuration of this local agent specifies to ignore them")
	}
	return nil
}

func (p *Profile) SetupGateway() error {
	out := os.Getenv("WG_GATEWAY_OUTBOUND_INTERFACE")
	if out == "" {
		return errors.New("WG_GATEWAY_OUTBOUND_INTERFACE is not defined. Add this to the environment to determine which interface should be used for outbound routing of the gateway")
	}
	err := exec.Command("bash", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward").Run()
	if err != nil {
		return err
	}
	err = exec.Command("iptables", "-t", "nat", "-F").Run()
	if err != nil {
		return err
	}
	err = exec.Command("iptables", "-F").Run()
	if err != nil {
		return err
	}
	err = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", out, "-j", "MASQUERADE").Run()
	if err != nil {
		return err
	}
	err = exec.Command("iptables", "-A", "FORWARD", "-i", out, "-o", "wg0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	if err != nil {
		return err
	}
	err = exec.Command("iptables", "-A", "FORWARD", "-i", "wg0", "-o", out, "-j", "ACCEPT").Run()
	if err != nil {
		return err
	}

	return nil
}

type PeerProfile struct {
	remoteclients.Peer
}

func GetPeerProfile(id string) (PeerProfile, error) {
	var p PeerProfile
	var err error
	err = GetAPIClient().Call(APIClientCtx, "GET", "/api/v1/remote_clients/peer/"+id, &p)

	pkey, err := base64.URLEncoding.DecodeString(p.PublicKey)
	sharedutils.CheckError(err)
	p.PublicKey = base64.StdEncoding.EncodeToString(pkey)

	return p, err
}
