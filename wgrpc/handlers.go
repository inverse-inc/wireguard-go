package wgrpc

import (
	context "context"
	"fmt"
	"os"
	sync "sync"
	"syscall"
	"time"

	"github.com/inverse-inc/wireguard-go/ztn"
)

type Debugable interface {
	PrintDebug()
}

type WGServiceServerHandler struct {
	sync.Mutex
	UnimplementedWGServiceServer
	connection *ztn.Connection
	debugables []Debugable
	onexit     func()
}

func NewWGServiceServerHandler(connection *ztn.Connection, onexit func()) *WGServiceServerHandler {
	return &WGServiceServerHandler{
		connection: connection,
		debugables: []Debugable{},
		onexit:     onexit,
	}
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
	// Kill the master process if we're master controlled
	if len(os.Args[2]) >= 2 && os.Args[2] == "--master-controlled" {
		syscall.Kill(os.Getppid(), syscall.SIGTERM)
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
