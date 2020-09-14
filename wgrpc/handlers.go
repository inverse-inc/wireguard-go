package wgrpc

import (
	context "context"
	"sync"
)

const (
	STATUS_CONNECTED = "CONNECTED"
	STATUS_ERROR     = "ERROR"
	STATUS_NOT_READY = ""
)

type WGServiceServerHandler struct {
	UnimplementedWGServiceServer
	sync.Mutex
	status    string
	lastError error
}

func NewWGServiceServerHandler() *WGServiceServerHandler {
	return &WGServiceServerHandler{}
}

func (s *WGServiceServerHandler) UpdateStatus(status string, err error) {
	s.Lock()
	defer s.Unlock()
	s.status = status
	s.lastError = err
}

func (s *WGServiceServerHandler) GetStatus(ctx context.Context, in *StatusRequest) (*StatusReply, error) {
	errStr := ""
	if s.lastError != nil {
		errStr = s.lastError.Error()
	}
	return &StatusReply{Status: s.status, LastError: errStr}, nil
}
