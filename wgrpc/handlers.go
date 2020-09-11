package wgrpc

import (
	context "context"
	"sync"
)

type WGServiceServerHandler struct {
	UnimplementedWGServiceServer
	sync.Mutex
	status string
}

func NewWGServiceServerHandler() *WGServiceServerHandler {
	return &WGServiceServerHandler{}
}

func (s *WGServiceServerHandler) UpdateStatus(status string) {
	s.Lock()
	defer s.Unlock()
	s.status = status
}

func (s *WGServiceServerHandler) GetStatus(ctx context.Context, in *StatusRequest) (*StatusReply, error) {
	return &StatusReply{Status: s.status}, nil
}
