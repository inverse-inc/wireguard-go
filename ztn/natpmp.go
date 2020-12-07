package ztn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
	"github.com/theckman/go-securerandom"
)

type NATPMP struct {
	sync.Mutex
	BindTechniqueBase
	mapping    natpmp.Client
	remotePort int
}

func NewNATPMP() *NATPMP {
	u := &NATPMP{mapping: natpmp.Client{}}
	u.InitID()
	return u
}

func (u *NATPMP) CheckNet() error {
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		return err
	}

	u.mapping = *natpmp.NewClient(gatewayIP)

	myExternalIP, err := u.ExternalIPAddr()

	if err != nil {
		return err
	}

	if isPrivateIP(myExternalIP) {
		return errors.New("External IP is a private ip")
	}
	return nil
}

func (u *NATPMP) ExternalIPAddr() (net.IP, error) {
	response, err := u.mapping.GetExternalAddress()
	if err != nil {
		return nil, err
	}
	return net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", response.ExternalIPAddress[0], response.ExternalIPAddress[1], response.ExternalIPAddress[2], response.ExternalIPAddress[3])), nil
}

func (u *NATPMP) AddPortMapping(localPort, remotePort int) error {

	if _, err := u.mapping.AddPortMapping("udp", localPort, remotePort, PublicPortTTL()); err == nil {
		fmt.Println("Port mapped successfully")
		return nil
	}
	return errors.New("Fail to add the port mapping")
}

func (u *NATPMP) BindRequestPkt(externalIP net.IP, externalPort int) []byte {
	var buf = defaultBufferPool.Get()
	u.AddIDToPacket(buf)
	buf[len(u.id)+1] = externalIP[12]
	buf[len(u.id)+2] = externalIP[13]
	buf[len(u.id)+3] = externalIP[14]
	buf[len(u.id)+4] = externalIP[15]
	binary.PutUvarint(buf[len(u.id)+5:], uint64(externalPort))
	return buf
}

func (u *NATPMP) ParseBindRequestPkt(buf []byte) (net.IP, int, error) {
	ip := net.IPv4(buf[len(u.id)+1], buf[len(u.id)+2], buf[len(u.id)+3], buf[len(u.id)+4])
	port, _ := binary.Uvarint(buf[len(u.id)+5:])
	return ip, int(port), nil
}

func (u *NATPMP) BindRequest(localPeerConn *net.UDPConn, localPeerPort int, sendTo chan *pkt) error {
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
