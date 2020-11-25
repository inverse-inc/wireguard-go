package peerrpc

import (
	context "context"
	"fmt"
	sync "sync"

	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn"
	"github.com/theckman/go-securerandom"
)

type PeerServiceServerHandler struct {
	sync.Mutex
	UnimplementedPeerServiceServer
	logger      *device.Logger
	peerBridges []*ztn.NetworkConnection
}

func NewPeerServiceServerHandler(logger *device.Logger) *PeerServiceServerHandler {
	return &PeerServiceServerHandler{logger: logger, peerBridges: []*ztn.NetworkConnection{}}
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
	s.peerBridges = append(s.peerBridges, nc)

	return &SetupForwardingReply{Id: nc.ID(), Token: token, Raddr: addr.String()}, nil
}
