package ztn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/upnp"
	"github.com/theckman/go-securerandom"
)

var upnpigdMapped = []UPNPIGD{}

type UPNPIGD struct {
	sync.Mutex
	BindTechniqueBase
	mapping    upnp.Upnp
	remotePort int
}

func NewUPNPIGD() *UPNPIGD {
	u := &UPNPIGD{mapping: upnp.Upnp{}}
	u.InitID()
	return u
}

func UPNPIGDCleanupMapped() {
	for _, u := range upnpigdMapped {
		fmt.Println("Clearing UPNPIGD mapping", u.remotePort)
		u.DelPortMapping()
	}
}

func (u *UPNPIGD) CheckNet() error {
	err := u.mapping.SearchGateway()
	if err != nil {
		return err
	}
	myExternalIP, err := u.ExternalIPAddr()
	if err != nil {
		return err
	}

	if isPrivateIP(myExternalIP) {
		return errors.New("External IP is a private ip")
	}
	return nil
}

func (u *UPNPIGD) ExternalIPAddr() (net.IP, error) {
	err := u.mapping.ExternalIPAddr()
	if err != nil {
		return nil, err
	}
	return net.ParseIP(u.mapping.GatewayOutsideIP), nil
}

func (u *UPNPIGD) DelPortMapping() error {
	u.mapping.DelPortMapping(u.remotePort, "UDP")
	return nil
}

func (u *UPNPIGD) AddPortMapping(localPort, remotePort int) error {
	if err := u.mapping.AddPortMapping(localPort, remotePort, PublicPortTTL(), "UDP", "PacketFence-Zero-Trust-Client"); err == nil {
		fmt.Println("Port mapped successfully", localPort, remotePort)
		upnpigdMapped = append(upnpigdMapped, *u)
		return nil
	} else {
		u.remotePort = 0
		return errors.New("Fail to add the port mapping")
	}
}

func (u *UPNPIGD) BindRequestPkt(externalIP net.IP, externalPort int) []byte {
	var buf = defaultBufferPool.Get()
	u.AddIDToPacket(buf)
	buf[len(u.id)+1] = externalIP[12]
	buf[len(u.id)+2] = externalIP[13]
	buf[len(u.id)+3] = externalIP[14]
	buf[len(u.id)+4] = externalIP[15]
	binary.PutUvarint(buf[len(u.id)+5:], uint64(externalPort))
	return buf
}

func (u *UPNPIGD) ParseBindRequestPkt(buf []byte) (net.IP, int, error) {
	ip := net.IPv4(buf[len(u.id)+1], buf[len(u.id)+2], buf[len(u.id)+3], buf[len(u.id)+4])
	port, _ := binary.Uvarint(buf[len(u.id)+5:])
	return ip, int(port), nil
}

func (u *UPNPIGD) BindRequest(localPeerConn *net.UDPConn, localPeerPort int, sendTo chan *pkt) error {
	u.Lock()
	defer u.Unlock()

	err := u.CheckNet()
	if err != nil {
		return errors.New("your router does not support the UPnP protocol.")
	}

	myExternalIP, err := u.ExternalIPAddr()
	if err != nil {
		return err
	}

	if u.remotePort == 0 {
		r, err := securerandom.Uint64()
		sharedutils.CheckError(err)
		u.remotePort = int(r%10000 + 30000)
		err = u.AddPortMapping(localPeerPort, u.remotePort)

		if err != nil {
			return errors.New("Fail to add the port mapping")
		}
	}

	go func() {
		sendTo <- &pkt{message: u.BindRequestPkt(myExternalIP, u.remotePort)}
	}()

	return nil
}
