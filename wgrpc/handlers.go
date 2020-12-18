package wgrpc

import (
	context "context"
	"fmt"
	"os"
	sync "sync"
	"time"

	"github.com/inverse-inc/wireguard-go/ztn"
)

type Debugable interface {
	PrintDebug()
}

type WGServiceServerHandler struct {
	sync.Mutex
	UnimplementedWGServiceServer
	connection        *ztn.Connection
	networkConnection *ztn.NetworkConnection
	debugables        []Debugable
	onexit            func()
}

func NewWGServiceServerHandler(connection *ztn.Connection, onexit func()) *WGServiceServerHandler {
	s := &WGServiceServerHandler{
		connection: connection,
		debugables: []Debugable{},
		onexit:     onexit,
	}
	return s
}

func (s *WGServiceServerHandler) AddDebugable(d Debugable) {
	s.Lock()
	defer s.Unlock()
	s.debugables = append(s.debugables, d)
}

func (s *WGServiceServerHandler) GetStatus(ctx context.Context, in *StatusRequest) (*StatusReply, error) {
	s.connection.Lock()
	defer s.connection.Unlock()
	errStr := ""
	if s.connection.LastError != nil {
		errStr = s.connection.LastError.Error()
	}
	sr := &StatusReply{Status: s.connection.Status, LastError: errStr}
	if s.networkConnection != nil {
		sr.CurrentBindTechnique = string(s.networkConnection.BindTechnique)
	}
	return sr, nil
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
	// Kill the master process if we're master controlled
	if len(os.Args[2]) >= 2 && os.Args[2] == "--master-controlled" {
		stopMasterProcess()
	}
	time.Sleep(1 * time.Second)
	s.onexit()
	return &StopReply{}, nil
}

func (s *WGServiceServerHandler) PrintDebug(ctx context.Context, in *PrintDebugRequest) (*PrintDebugReply, error) {
	for _, d := range s.debugables {
		fmt.Println("Printing debug for", d)
		d.PrintDebug()
	}
	return &PrintDebugReply{}, nil
}

func (s *WGServiceServerHandler) SetNetworkConnection(networkConnection *ztn.NetworkConnection) {
	s.networkConnection = networkConnection
}
