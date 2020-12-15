package ztn

import (
	"runtime/debug"
	"sync"

	"github.com/inverse-inc/wireguard-go/device"
)

type Connection struct {
	sync.Mutex
	Profile   *Profile
	Peers     map[string]*PeerConnection
	Status    string
	LastError error

	logger *device.Logger
}

func NewConnection(logger *device.Logger) *Connection {
	return &Connection{Peers: map[string]*PeerConnection{}, logger: logger}
}

func (c *Connection) Update(f func()) {
	c.Lock()
	defer c.Unlock()
	f()
}

func (c *Connection) StartPeer(device *device.Device, profile Profile, peerID string, networkConnection *NetworkConnection) {
	c.Lock()
	defer c.Unlock()
	if c.Peers[peerID] != nil {
		c.logger.Debug.Println("Not starting", peerID, "since its already in the known peers")
		return
	}

	peerProfile, err := GetPeerProfile(peerID)
	if err != nil {
		c.logger.Error.Println("Unable to fetch profile for peer", peerID, ". Error:", err)
		c.logger.Error.Println(debug.Stack())
	} else {
		c.logger.Info.Println("Starting connection to peer", peerID)
		c.Peers[peerID] = NewPeerConnection(device, c.logger, profile, peerProfile, networkConnection)
		go func(peerID string, peerProfile PeerProfile, pc *PeerConnection) {
			for {
				func() {
					defer func() {
						if r := recover(); r != nil {
							c.logger.Error.Println("Recovered error", r, "while handling peer", peerProfile.PublicKey, ". Will attempt to connect to it again.")
							debug.PrintStack()
						}
					}()
					pc.Start()
				}()
			}
		}(peerID, peerProfile, c.Peers[peerID])
	}
}
