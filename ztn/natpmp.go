package ztn

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
	securerandom "github.com/theckman/go-securerandom"
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

	// Test if the port mapping works, open random port for 5s and test the return error
	r, err := securerandom.Uint64()
	randomPort := int(r%10000 + 30000)

	if _, err := u.mapping.AddPortMapping("udp", randomPort, randomPort, 5); err == nil {
		fmt.Println("Port mapped successfully")
		return nil
	} else {
		return errors.New("Not able to open a port via NATPMP")
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

		// Refresh the port translation
		go func() {
			for {
				time.Sleep((time.Duration(PublicPortTTL()) + 10*time.Second) * time.Second)
				_, err = u.mapping.AddPortMapping("udp", localPort, remotePort, PublicPortTTL())
			}
		}()
		return nil
	}
	return errors.New("Fail to add the port mapping")
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
