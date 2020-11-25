package wgrpc

import (
	context "context"
	"os"
	"time"

	"github.com/inverse-inc/wireguard-go/ztn"
)

type WGServiceServerHandler struct {
	UnimplementedWGServiceServer
	connection        *ztn.Connection
	NetworkConnection *ztn.NetworkConnection
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
			peerReplies = append(peerReplies, &PeerReply{
				IpAddress: pc.PeerProfile.WireguardIP.String(),
				Hostname:  pc.PeerProfile.Hostname,
				Status:    pc.Status,
			})
		}
	}
	return &PeersReply{Peers: peerReplies}, nil
}

func (s *WGServiceServerHandler) Stop(ctx context.Context, in *StopRequest) (*StopReply, error) {
	time.Sleep(1 * time.Second)
	os.Exit(0)
	return &StopReply{}, nil
}

func (s *WGServiceServerHandler) PrintDebug(ctx context.Context, in *PrintDebugRequest) (*PrintDebugReply, error) {
	if s.NetworkConnection != nil {
		s.NetworkConnection.PrintDebug()
	}
	return &PrintDebugReply{}, nil
}
