package natt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn/api"
	"github.com/inverse-inc/wireguard-go/ztn/bufferpool"
	"github.com/inverse-inc/wireguard-go/ztn/config"
	"github.com/inverse-inc/wireguard-go/ztn/constants"
	"github.com/inverse-inc/wireguard-go/ztn/profile"
	"github.com/inverse-inc/wireguard-go/ztn/util"
	"github.com/scottjg/upnp"
)

var mapping = new(upnp.Upnp)

var localPort = constants.LocalWGPort
var remotePort = constants.LocalWGPort

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
func (hole *UPnPIGD) init(context context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) {
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
	hole.ConnectionPeer = e
}

// GetExternalInfo fetch wan information
func (hole *UPnPIGD) GetExternalInfo() error {
	err := CheckNet()
	if err != nil {
		return errors.New("your router does not support the UPnP protocol.")
	}

	myExternalIP, err := ExternalIPAddr()
	if err != nil {
		return err
	}
	MyUDP := &net.UDPAddr{IP: myExternalIP, Port: remotePort}
	hole.ConnectionPeer.MyAddr = MyUDP
	err = hole.AddPortMapping(localPort, remotePort)
	if err != nil {
		return errors.New("Fail to add the port mapping")
	}
	return nil
}

// AddPortMapping insert port mapping in the gateway
func (hole *UPnPIGD) AddPortMapping(localPort, remotePort int) error {
	if err := mapping.AddPortMapping(localPort, remotePort, 60, "UDP", "WireguardGO"); err == nil {
		fmt.Println("Port mapped successfully")
		hole.ConnectionPeer.Logger.Info.Print("Port mapped successfully")
		return nil
	}
	return errors.New("Fail to add the port mapping")
}

// DelPortMapping delete port mapping in the gateway
func DelPortMapping(localPort, remotePort int) {
	mapping.DelPortMapping(remotePort, "UDP")
}

// Run execute the Method
func (hole *UPnPIGD) Start() error {
	var err error
	err = hole.GetExternalInfo()

	hole.ConnectionPeer.LocalPeerConn, err = net.ListenUDP(udp, nil)
	sharedutils.CheckError(err)

	hole.ConnectionPeer.Logger.Debug.Printf("Listening on %s for peer %s\n", hole.ConnectionPeer.LocalPeerConn.LocalAddr(), hole.ConnectionPeer.PeerID)

	messageChan := make(chan *pkt)
	hole.ConnectionPeer.Listen(hole.ConnectionPeer.LocalPeerConn, messageChan)

	var peerAddrChan <-chan string

	foundPeer := make(chan bool)

	a := strings.Split(hole.ConnectionPeer.LocalPeerConn.LocalAddr().String(), ":")
	var localPeerAddr = fmt.Sprintf("%s:%s", constants.LocalWGIP.String(), a[len(a)-1])
	// var localWGAddr = fmt.Sprintf("%s:%d", constants.LocalWGIP.String(), constants.LocalWGPort)

	for {
		res := func() bool {
			var message *pkt
			// var ok bool

			defer func() {
				if message != nil {
					bufferpool.DefaultBufferPool.Put(message.message)
				}
			}()

			select {

			case peerStr := <-peerAddrChan:
				if hole.ConnectionPeer.ShouldTryPrivate() {
					hole.ConnectionPeer.Logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", hole.ConnectionPeer.PeerID, ". This connection attempt may fail")
				}

				hole.ConnectionPeer.Logger.Debug.Println("Publishing for peer join", hole.ConnectionPeer.PeerID)
				api.GLPPublish(hole.ConnectionPeer.BuildP2PKey(), hole.ConnectionPeer.BuildNetworkEndpointEvent(hole))

				hole.ConnectionPeer.PeerAddr, err = net.ResolveUDPAddr(udp, peerStr)
				if err != nil {
					// pc.Logger.Fatalln("resolve peeraddr:", err)
				}
				conf := ""
				conf += fmt.Sprintf("public_key=%s\n", util.KeyToHex(hole.ConnectionPeer.PeerProfile.PublicKey))
				conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
				conf += "replace_allowed_ips=true\n"
				conf += fmt.Sprintf("allowed_ip=%s/32\n", hole.ConnectionPeer.PeerProfile.WireguardIP.String())

				config.SetConfigMulti(hole.ConnectionPeer.Device, conf)

				hole.ConnectionPeer.Started = true
				hole.ConnectionPeer.TriedPrivate = true
				foundPeer <- true
			}
			return true
		}()
		if !res {
			return errors.New("Failed upnpigd")
		}
	}
}

func (hole *UPnPIGD) GetPrivateAddr() string {
	return "mysuperipzammit"
}
