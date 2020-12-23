package ztn

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/upnp"
	securerandom "github.com/theckman/go-securerandom"
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
	// Remove all the mapping
	var mapping = new(upnp.Upnp)
	mapping.SearchGateway()
	ExistingMapping := mapping.GetListOfPortMappings("UDP")
	NetworkInterfaces, err := net.Interfaces()
	if err == nil {
		for _, Int := range NetworkInterfaces {
			eth, err := net.InterfaceByName(Int.Name)
			if err != nil {
				continue
			}
			adresses, _ := eth.Addrs()
			for _, adresse := range adresses {
				for _, Mapping := range ExistingMapping {
					IP, _, _ := net.ParseCIDR(adresse.String())
					if Mapping.NewInternalClient == IP.String() {
						match, _ := regexp.MatchString("ZTN", Mapping.NewDescription)
						if match {
							fmt.Println("Clearing UPNPIGD mapping", Mapping.NewExternalPort)
							port, _ := strconv.Atoi(Mapping.NewExternalPort)
							mapping.DelPortMapping(port, "UDP")
						}
					}
				}
			}
		}
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

	if err := u.mapping.AddPortMapping(localPort, remotePort, PublicPortTTL(), "UDP", "ZTN-"+strconv.Itoa(remotePort)+"-"+strconv.Itoa(localPort)); err == nil {
		fmt.Println("Port mapped successfully", localPort, remotePort)
		upnpigdMapped = append(upnpigdMapped, *u)
		// Refresh the port translation
		go func() {
			for {
				time.Sleep(time.Duration(PublicPortTTL()) * time.Second)
				issucess := u.mapping.DelPortMapping(remotePort, "UDP")
				if issucess {
					fmt.Println("Successufully closed the mapped port", localPort, remotePort)
					err = u.mapping.AddPortMapping(localPort, remotePort, PublicPortTTL(), "UDP", "ZTN-"+strconv.Itoa(remotePort)+"-"+strconv.Itoa(localPort))
					if err != nil {
						fmt.Println("Failed to reopen the mapped port", localPort, remotePort)
					} else {
						fmt.Println("Port reopen successfully", localPort, remotePort)
					}
				}
			}
		}()
		return nil
	} else {
		u.remotePort = 0
		return errors.New("Fail to add the port mapping")
	}
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
