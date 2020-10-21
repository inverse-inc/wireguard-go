package natt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn/api"
	"github.com/inverse-inc/wireguard-go/ztn/bufferpool"
	"github.com/inverse-inc/wireguard-go/ztn/config"
	"github.com/inverse-inc/wireguard-go/ztn/constants"
	"github.com/inverse-inc/wireguard-go/ztn/profile"
	"github.com/inverse-inc/wireguard-go/ztn/util"
)

var localWGIP = net.ParseIP("127.0.0.1")

const localWGPort = 6969

// ExternalConnection struct
type ExternalConnection struct {
	myID        string
	PeerID      string
	MyProfile   profile.Profile
	PeerProfile profile.PeerProfile

	WgConn        *net.UDPConn
	LocalPeerConn *net.UDPConn
	Device        *device.Device
	Logger        *device.Logger

	MyAddr   *net.UDPAddr
	PeerAddr *net.UDPAddr

	Started       bool
	Connected     bool
	LastKeepalive time.Time

	TriedPrivate bool
	Ctx          context.Context
}

// Method interface
type Method interface {
	Start() error
	GetPrivateAddr() string
}

// Creater function
type Creater func(context.Context, *device.Device, *device.Logger, profile.Profile, profile.PeerProfile) (Method, error)

var methodLookup = map[string]Creater{
	"stun":    NewSTUN,
	"upnpigd": NewUPnPIGD,
	"natpmp":  NewNatPMP,
}

// Create function
func Create(ctx context.Context, method string, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) (Method, error) {
	if creater, found := methodLookup[method]; found {
		return creater(ctx, d, logger, myProfile, peerProfile)
	}

	return nil, fmt.Errorf("Method of %s not found", method)
}

func (ext *ExternalConnection) Listen(conn *net.UDPConn, messages chan *pkt) {
	go func() {
		for {
			buf := bufferpool.DefaultBufferPool.Get()

			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				close(messages)
				return
			}
			buf = buf[:n]

			messages <- &pkt{raddr: raddr, message: buf}
		}
	}()
}

func (ext *ExternalConnection) BuildP2PKey() string {
	key1 := ext.MyProfile.PublicKey
	key2 := ext.PeerProfile.PublicKey
	if key2 < key1 {
		key1bak := key1
		key1 = key2
		key2 = key1bak
	}

	key1dec, err := base64.StdEncoding.DecodeString(key1)
	sharedutils.CheckError(err)
	key2dec, err := base64.StdEncoding.DecodeString(key2)
	sharedutils.CheckError(err)

	combined := append(key1dec, key2dec...)
	return base64.URLEncoding.EncodeToString(combined)
}

func (ext *ExternalConnection) BuildNetworkEndpointEvent(method Method) api.Event {
	return api.Event{Type: "network_endpoint", Data: gin.H{
		"id":               ext.MyProfile.PublicKey,
		"public_endpoint":  ext.MyAddr.String(),
		"private_endpoint": method.GetPrivateAddr(),
	}}
}

func (ext *ExternalConnection) GetPeerAddr() <-chan string {
	result := make(chan string)
	myID := ext.MyProfile.PublicKey

	p2pk := ext.BuildP2PKey()

	go func() {
		c := api.GLPClient(p2pk)
		c.Start(api.APIClientCtx)
		for {
			select {
			case e := <-c.EventsChan:
				event := api.Event{}
				err := json.Unmarshal(e.Data, &event)
				sharedutils.CheckError(err)
				if event.Type == "network_endpoint" && event.Data["id"].(string) != myID {
					if ext.ShouldTryPrivate() {
						result <- event.Data["private_endpoint"].(string)
						return
					} else {
						result <- event.Data["public_endpoint"].(string)
						return
					}
				}
			}
		}
	}()

	return result
}

func (ext *ExternalConnection) ShouldTryPrivate() bool {
	return !ext.TriedPrivate
}

func (ext *ExternalConnection) reset() {
	ext.WgConn = nil
	ext.LocalPeerConn = nil
	ext.MyAddr = nil
	ext.PeerAddr = nil
	ext.Started = false
	ext.LastKeepalive = time.Time{}

	// Reset the triedPrivate flag if a connection attempt was already successful so that it retries from scratch next time
	if ext.Connected {
		ext.TriedPrivate = false
	}
	ext.Connected = false
}

func (ext *ExternalConnection) SetConfig(External *ExternalConnection, localPeerAddr string) {
	if localPeerAddr == "" {
		localPeerAddr = "169.254.0.254:" + strconv.Itoa(constants.LocalWGPort)
	}
	conf := ""
	conf += fmt.Sprintf("public_key=%s\n", util.KeyToHex(External.PeerProfile.PublicKey))
	conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
	conf += "replace_allowed_ips=true\n"
	conf += fmt.Sprintf("allowed_ip=%s/32\n", External.PeerProfile.WireguardIP.String())

	config.SetConfigMulti(External.Device, conf)
}
