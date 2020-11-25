// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package peerrpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// PeerServiceClient is the client API for PeerService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PeerServiceClient interface {
	CanOfferForwarding(ctx context.Context, in *CanOfferForwardingRequest, opts ...grpc.CallOption) (*CanOfferForwardingReply, error)
	SetupForwarding(ctx context.Context, in *SetupForwardingRequest, opts ...grpc.CallOption) (*SetupForwardingReply, error)
}

type peerServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPeerServiceClient(cc grpc.ClientConnInterface) PeerServiceClient {
	return &peerServiceClient{cc}
}

func (c *peerServiceClient) CanOfferForwarding(ctx context.Context, in *CanOfferForwardingRequest, opts ...grpc.CallOption) (*CanOfferForwardingReply, error) {
	out := new(CanOfferForwardingReply)
	err := c.cc.Invoke(ctx, "/PeerService/CanOfferForwarding", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *peerServiceClient) SetupForwarding(ctx context.Context, in *SetupForwardingRequest, opts ...grpc.CallOption) (*SetupForwardingReply, error) {
	out := new(SetupForwardingReply)
	err := c.cc.Invoke(ctx, "/PeerService/SetupForwarding", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PeerServiceServer is the server API for PeerService service.
// All implementations must embed UnimplementedPeerServiceServer
// for forward compatibility
type PeerServiceServer interface {
	CanOfferForwarding(context.Context, *CanOfferForwardingRequest) (*CanOfferForwardingReply, error)
	SetupForwarding(context.Context, *SetupForwardingRequest) (*SetupForwardingReply, error)
	mustEmbedUnimplementedPeerServiceServer()
}

// UnimplementedPeerServiceServer must be embedded to have forward compatible implementations.
type UnimplementedPeerServiceServer struct {
}

func (UnimplementedPeerServiceServer) CanOfferForwarding(context.Context, *CanOfferForwardingRequest) (*CanOfferForwardingReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CanOfferForwarding not implemented")
}
func (UnimplementedPeerServiceServer) SetupForwarding(context.Context, *SetupForwardingRequest) (*SetupForwardingReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetupForwarding not implemented")
}
func (UnimplementedPeerServiceServer) mustEmbedUnimplementedPeerServiceServer() {}

// UnsafePeerServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PeerServiceServer will
// result in compilation errors.
type UnsafePeerServiceServer interface {
	mustEmbedUnimplementedPeerServiceServer()
}

func RegisterPeerServiceServer(s grpc.ServiceRegistrar, srv PeerServiceServer) {
	s.RegisterService(&_PeerService_serviceDesc, srv)
}

func _PeerService_CanOfferForwarding_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CanOfferForwardingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PeerServiceServer).CanOfferForwarding(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/PeerService/CanOfferForwarding",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PeerServiceServer).CanOfferForwarding(ctx, req.(*CanOfferForwardingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PeerService_SetupForwarding_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetupForwardingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PeerServiceServer).SetupForwarding(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/PeerService/SetupForwarding",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PeerServiceServer).SetupForwarding(ctx, req.(*SetupForwardingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _PeerService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "PeerService",
	HandlerType: (*PeerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CanOfferForwarding",
			Handler:    _PeerService_CanOfferForwarding_Handler,
		},
		{
			MethodName: "SetupForwarding",
			Handler:    _PeerService_SetupForwarding_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "peerrpc.proto",
}
