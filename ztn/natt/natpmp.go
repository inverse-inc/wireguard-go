package natt

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/upnp"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn/api"
	"github.com/inverse-inc/wireguard-go/ztn/bufferpool"
	"github.com/inverse-inc/wireguard-go/ztn/constants"
	"github.com/inverse-inc/wireguard-go/ztn/profile"
	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
)

var mappingUpnp = new(upnp.Upnp)

// NatPMP struct
type NatPMP struct {
	ConnectionPeer *ExternalConnection
}

// CheckNet search for a gateway
func (natt *NatPMP) CheckNet() error {
	_, err := gateway.DiscoverGateway()
	return err
}

// ExternalIPAddr return the WAN ip
func (natt *NatPMP) ExternalIPAddr() (net.IP, error) {
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, err
	}

	client := natpmp.NewClient(gatewayIP)

	response, err := client.GetExternalAddress()
	if err != nil {
		return nil, err
	}
	fmt.Printf("External IP address: %v\n", response.ExternalIPAddress)

	if err != nil {
		return nil, err
	}
	return net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", response.ExternalIPAddress[0], response.ExternalIPAddress[1], response.ExternalIPAddress[2], response.ExternalIPAddress[3])), nil

}

// NewNatPMP Init
func NewNatPMP(ctx context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) (Method, error) {
	method := NatPMP{}
	method.init(ctx, d, logger, myProfile, peerProfile)
	return &method, nil
}

// Init initialyse
func (natt *NatPMP) init(context context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) {
	log.SetProcessName("wireguard-go")
	ctx := log.LoggerNewContext(context)
	e := &ExternalConnection{
		Device:      d,
		Logger:      logger,
		myID:        myProfile.PublicKey,
		PeerID:      peerProfile.PublicKey,
		MyProfile:   myProfile,
		PeerProfile: peerProfile,
		Ctx:         ctx,
	}
	natt.ConnectionPeer = e
}

// GetExternalInfo fetch wan information
func (natt *NatPMP) GetExternalInfo() error {
	err := natt.CheckNet()
	if err != nil {
		return errors.New("Your router does not support the NAT PMP protocol !")
	}

	myExternalIP, err := natt.ExternalIPAddr()
	if err != nil {
		return err
	}

	remotePort := rand.Intn(constants.HigherPort-constants.LowerPort) + constants.LowerPort

	MyUDP := &net.UDPAddr{IP: myExternalIP, Port: remotePort}
	natt.ConnectionPeer.MyAddr = MyUDP
	err = natt.AddPortMapping(localPort, remotePort)
	if err != nil {
		return errors.New("Fail to add the port mapping")
	}
	return nil
}

// AddPortMapping insert port mapping in the gateway
func (natt *NatPMP) AddPortMapping(localPort, remotePort int) error {
	if err := mappingUpnp.AddPortMapping(localPort, remotePort, 60, "UDP", "WireguardGO"); err == nil {
		fmt.Println("Port mapped successfully")
		natt.ConnectionPeer.Logger.Info.Print("Port mapped successfully")
		return nil
	}
	return errors.New("Fail to add the port mapping")
}

// DelPortMapping delete port mapping in the gateway
func DelPortMapping(localPort, remotePort int) {
	mappingUpnp.DelPortMapping(remotePort, "UDP")
}

// Start method for NAT PMP
func (natt *NatPMP) Start() error {
	var err error
	err = natt.GetExternalInfo()

	api.GLPPublish(natt.ConnectionPeer.BuildP2PKey(), natt.ConnectionPeer.BuildNetworkEndpointEvent(natt))

	var peerAddrChan <-chan string

	foundPeer := make(chan bool)

	peerAddrChan = natt.ConnectionPeer.GetPeerAddr()

	for {
		res := func() bool {
			var message *pkt

			defer func() {
				if message != nil {
					bufferpool.DefaultBufferPool.Put(message.message)
				}
			}()

			select {

			case peerStr := <-peerAddrChan:
				if natt.ConnectionPeer.ShouldTryPrivate() {
					natt.ConnectionPeer.Logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", natt.ConnectionPeer.PeerID, ". This connection attempt may fail")
				}

				natt.ConnectionPeer.PeerAddr, err = net.ResolveUDPAddr(udp, peerStr)

				a := strings.Split(peerStr, ":")
				var localPeerAddr = fmt.Sprintf("%s:%s", constants.LocalWGIP.String(), a[len(a)-1])
				if err != nil {
					// pc.Logger.Fatalln("resolve peeraddr:", err)
				}
				natt.ConnectionPeer.SetConfig(natt.ConnectionPeer, localPeerAddr)

				natt.ConnectionPeer.Started = true
				natt.ConnectionPeer.TriedPrivate = true
				foundPeer <- true
			}
			return true
		}()

		if !res {
			return errors.New("Failed NAT PMP")
		}
	}
}

func (natt *NatPMP) GetPrivateAddr() string {
	_, ip, err := natt.ConnectionPeer.MyProfile.FindClientMAC()
	if err != nil {
	}
	return ip.IP.String() + ":" + strconv.Itoa(constants.LocalWGPort)
}
