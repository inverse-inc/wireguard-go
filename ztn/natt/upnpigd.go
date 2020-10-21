package natt

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"

	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/upnp"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn/api"
	"github.com/inverse-inc/wireguard-go/ztn/bufferpool"
	"github.com/inverse-inc/wireguard-go/ztn/constants"
	"github.com/inverse-inc/wireguard-go/ztn/profile"
)

var mapping = new(upnp.Upnp)

var localPort = constants.LocalWGPort

// UPnPIGD struct
type UPnPIGD struct {
	ConnectionPeer *ExternalConnection
}

// CheckNet search for a gateway
func CheckNet() error {
	err := mapping.SearchGateway()
	return err
}

// ExternalIPAddr return the WAN ip
func ExternalIPAddr() (net.IP, error) {
	err := mapping.ExternalIPAddr()
	if err != nil {
		return nil, err
	}
	return net.ParseIP(mapping.GatewayOutsideIP), nil

}

// NewUPnPIGD Init
func NewUPnPIGD(ctx context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) (Method, error) {
	method := UPnPIGD{}
	method.init(ctx, d, logger, myProfile, peerProfile)
	return &method, nil
}

// Init initialyse
func (natt *UPnPIGD) init(context context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) {
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
func (natt *UPnPIGD) GetExternalInfo() error {
	err := CheckNet()
	if err != nil {

		return errors.New("your router does not support the UPnP protocol.")
	}

	myExternalIP, err := ExternalIPAddr()
	if err != nil {
		return err
	}

	if natt.ConnectionPeer.MyAddr != nil && natt.ConnectionPeer.MyAddr.IP.Equal(myExternalIP) {

		err = natt.AddPortMapping(localPort, natt.ConnectionPeer.MyAddr.Port)

	} else {
		remotePort := rand.Intn(constants.HigherPort-constants.LowerPort) + constants.LowerPort

		MyUDP := &net.UDPAddr{IP: myExternalIP, Port: remotePort}
		natt.ConnectionPeer.MyAddr = MyUDP

		err = natt.AddPortMapping(localPort, remotePort)

	}
	if err != nil {
		return errors.New("Fail to add the port mapping")
	}
	return nil
}

// AddPortMapping insert port mapping in the gateway
func (natt *UPnPIGD) AddPortMapping(localPort, remotePort int) error {
	if err := mapping.AddPortMapping(localPort, remotePort, 60, "UDP", "WireguardGO"); err == nil {
		fmt.Println("Port mapped successfully")
		natt.ConnectionPeer.Logger.Info.Print("Port mapped successfully")
		return nil
	}
	return errors.New("Fail to add the port mapping")
}

// DelPortMapping delete port mapping in the gateway
func (natt *UPnPIGD) DelPortMapping(localPort, remotePort int) {
	mapping.DelPortMapping(remotePort, "UDP")
}

// Run execute the Method
func (natt *UPnPIGD) Start() error {
	var err error
	err = natt.GetExternalInfo()

	api.GLPPublish(natt.ConnectionPeer.BuildP2PKey(), natt.ConnectionPeer.BuildNetworkEndpointEvent(natt))

	var peerAddrChan <-chan string

	foundPeer := make(chan bool)

	peerAddrChan = natt.ConnectionPeer.GetPeerAddr()

	natt.ConnectionPeer.TriedPrivate = true

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

				natt.ConnectionPeer.SetConfig(natt.ConnectionPeer, peerStr)

				natt.ConnectionPeer.Started = true
				natt.ConnectionPeer.TriedPrivate = true
				foundPeer <- true
			}
			return true
		}()

		if !res {
			return errors.New("Failed upnpigd")
		}
	}
}

func (natt *UPnPIGD) GetPrivateAddr() string {
	_, ip, err := natt.ConnectionPeer.MyProfile.FindClientMAC()
	if err != nil {
	}
	return ip.IP.String() + ":" + strconv.Itoa(constants.LocalWGPort)
}
