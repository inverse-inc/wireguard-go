package ztn

import (
	context "context"
	"errors"
	"fmt"
	sync "sync"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
)

type PeerServiceServerHandler struct {
	sync.Mutex
	UnimplementedPeerServiceServer
	logger         *device.Logger
	peerBridges    map[uint64]*NetworkConnection
	maxPeerBridges int
}

func NewPeerServiceServerHandler(logger *device.Logger) *PeerServiceServerHandler {
	s := &PeerServiceServerHandler{
		logger:         logger,
		peerBridges:    map[uint64]*NetworkConnection{},
		maxPeerBridges: sharedutils.EnvOrDefaultInt(EnvMaxPeerBridges, 16),
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
	if in.Name == "" {
		return nil, errors.New("Missing name for your connection")
	}

	s.Lock()
	if len(s.peerBridges) >= s.maxPeerBridges {
		s.Unlock()
		return nil, errors.New("Reached the maximum amount of peer bridges on this server")
	}
	s.Unlock()

	nc := NewNetworkConnection(fmt.Sprintf("peer-service-%s", in.Name), s.logger, 0)
	raddr, publicAddr := nc.SetupForwarding(in.PeerConnectionType)

	if raddr == nil || publicAddr == nil {
		return nil, errors.New("Unable to setup the forwarding")
	}

	s.Lock()
	defer s.Unlock()
	s.peerBridges[nc.Token()] = nc

	return &SetupForwardingReply{Id: nc.ID(), Token: nc.Token(), Raddr: raddr.String(), PublicIP: publicAddr.IP[12:16], PublicPort: int32(publicAddr.Port)}, nil
}

func (s *PeerServiceServerHandler) ForwardingIsAlive(ctx context.Context, in *ForwardingIsAliveRequest) (*ForwardingIsAliveReply, error) {
	s.Lock()
	defer s.Unlock()
	if nc, ok := s.peerBridges[in.Token]; ok {
		if nc.ID() == in.Id {
			return &ForwardingIsAliveReply{Result: true}, nil
		}
	}
	return &ForwardingIsAliveReply{Result: false}, nil
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
