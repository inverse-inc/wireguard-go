package peerrpc

import (
	context "context"
	"errors"
	"fmt"
	sync "sync"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn"
	"github.com/theckman/go-securerandom"
)

type PeerServiceServerHandler struct {
	sync.Mutex
	UnimplementedPeerServiceServer
	logger         *device.Logger
	peerBridges    map[uint64]*ztn.NetworkConnection
	maxPeerBridges int
}

func NewPeerServiceServerHandler(logger *device.Logger) *PeerServiceServerHandler {
	s := &PeerServiceServerHandler{
		logger:         logger,
		peerBridges:    map[uint64]*ztn.NetworkConnection{},
		maxPeerBridges: sharedutils.EnvOrDefaultInt("WG_MAX_PEER_BRIDGES", 16),
	}
	go func() {
		for {
			select {
			case <-time.After(1 * time.Second):
				s.maintenance()
			}
		}
	}()
	return s
}

func (s *PeerServiceServerHandler) CanOfferForwarding(ctx context.Context, in *CanOfferForwardingRequest) (*CanOfferForwardingReply, error) {
	return &CanOfferForwardingReply{Result: true}, nil
}

func (s *PeerServiceServerHandler) SetupForwarding(ctx context.Context, in *SetupForwardingRequest) (*SetupForwardingReply, error) {
	s.Lock()
	if len(s.peerBridges) >= s.maxPeerBridges {
		s.Unlock()
		return nil, errors.New("Reached the maximum amount of peer bridges on this server")
	}
	s.Unlock()

	token, err := securerandom.Uint64()
	if err != nil {
		return nil, err
	}
	nc := ztn.NewNetworkConnection(fmt.Sprintf("peer-service-%d", token), s.logger)
	addr := nc.SetupForwarding()

	s.Lock()
	defer s.Unlock()
	s.peerBridges[token] = nc

	return &SetupForwardingReply{Id: nc.ID(), Token: token, Raddr: addr.String()}, nil
}

func (s *PeerServiceServerHandler) maintenance() {
	s.Lock()
	defer s.Unlock()
	toDel := []uint64{}
	for t, nc := range s.peerBridges {
		if !nc.CheckConnectionLiveness() {
			toDel = append(toDel, t)
		}
	}
	for _, t := range toDel {
		delete(s.peerBridges, t)
	}
}

func (s *PeerServiceServerHandler) PrintDebug() {
	s.Lock()
	defer s.Unlock()
	for _, nc := range s.peerBridges {
		nc.PrintDebug()
	}
	s.logger.Info.Printf("Got %d bridges active out of a maximum of %d", len(s.peerBridges), s.maxPeerBridges)
}
