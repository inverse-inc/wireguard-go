package wgrpc

import (
	context "context"

	"github.com/inverse-inc/wireguard-go/ztn"
)

type WGServiceServerHandler struct {
	UnimplementedWGServiceServer
	connection *ztn.Connection
}

func NewWGServiceServerHandler(connection *ztn.Connection) *WGServiceServerHandler {
	return &WGServiceServerHandler{connection: connection}
}

func (s *WGServiceServerHandler) GetStatus(ctx context.Context, in *StatusRequest) (*StatusReply, error) {
	s.connection.Lock()
	defer s.connection.Unlock()
	errStr := ""
	if s.connection.LastError != nil {
		errStr = s.connection.LastError.Error()
	}
	return &StatusReply{Status: s.connection.Status, LastError: errStr}, nil
}

func (s *WGServiceServerHandler) GetPeers(ctx context.Context, in *PeersRequest) (*PeersReply, error) {
	s.connection.Lock()
	defer s.connection.Unlock()
	peerReplies := []*PeerReply{}
	for _, pc := range s.connection.Peers {
		if pc != nil {
			peerReplies = append(peerReplies, &PeerReply{IpAddress: pc.PeerProfile.WireguardIP.String(), Status: pc.Status})
		}
	}
	return &PeersReply{Peers: peerReplies}, nil
}
