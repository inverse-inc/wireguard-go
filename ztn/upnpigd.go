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
	id         uint64
	mapping    upnp.Upnp
	remotePort int
}

func NewUPNPGID() *UPNPIGD {
	id, err := securerandom.Uint64()
	sharedutils.CheckError(err)
	return &UPNPIGD{id: id, mapping: upnp.Upnp{}}
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

func (u *UPNPIGD) IsMessage(b []byte) bool {
	id, _ := binary.Uvarint(b[0:binary.MaxVarintLen64])
	if id == u.id {
		return true
	} else {
		return false
	}
}

func (u *UPNPIGD) BindRequestPkt(externalIP net.IP, externalPort int) []byte {
	var buf = defaultBufferPool.Get()
	binary.PutUvarint(buf, u.id)
	buf[binary.MaxVarintLen64+1] = externalIP[12]
	buf[binary.MaxVarintLen64+2] = externalIP[13]
	buf[binary.MaxVarintLen64+3] = externalIP[14]
	buf[binary.MaxVarintLen64+4] = externalIP[15]
	binary.PutUvarint(buf[binary.MaxVarintLen64+5:], uint64(externalPort))
	return buf
}

func (u *UPNPIGD) ParseBindRequestPkt(buf []byte) (net.IP, int, error) {
	ip := net.IPv4(buf[binary.MaxVarintLen64+1], buf[binary.MaxVarintLen64+2], buf[binary.MaxVarintLen64+3], buf[binary.MaxVarintLen64+4])
	port, _ := binary.Uvarint(buf[binary.MaxVarintLen64+5:])
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
