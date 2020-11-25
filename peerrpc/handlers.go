package peerrpc

import (
	context "context"
	"fmt"
	sync "sync"
	"time"

	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn"
	"github.com/theckman/go-securerandom"
)

type PeerServiceServerHandler struct {
	sync.Mutex
	UnimplementedPeerServiceServer
	logger      *device.Logger
	peerBridges map[uint64]*ztn.NetworkConnection
}

func NewPeerServiceServerHandler(logger *device.Logger) *PeerServiceServerHandler {
	s := &PeerServiceServerHandler{logger: logger, peerBridges: map[uint64]*ztn.NetworkConnection{}}
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
}
