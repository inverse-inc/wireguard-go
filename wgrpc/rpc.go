package wgrpc

import (
	"fmt"
	"net"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/peerrpc"
	"github.com/inverse-inc/wireguard-go/ztn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const ServerPort = 6970

var WGRPCServer *WGServiceServerHandler

func StartRPC(logger *device.Logger, connection *ztn.Connection) {
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ServerPort))
	sharedutils.CheckError(err)
	grpcServer := grpc.NewServer()

	WGRPCServer = NewWGServiceServerHandler(connection)
	RegisterWGServiceServer(grpcServer, WGRPCServer)

	PeerServer := peerrpc.NewPeerServiceServerHandler(logger)
	peerrpc.RegisterPeerServiceServer(grpcServer, PeerServer)

	WGRPCServer.AddDebugable(PeerServer)

	reflection.Register(grpcServer)
	grpcServer.Serve(lis)
}

func WGRPCClient() WGServiceClient {
	conn, err := grpc.Dial(
		fmt.Sprintf("127.0.0.1:%d", ServerPort),
		grpc.WithInsecure(),
	)
	sharedutils.CheckError(err)
	client := NewWGServiceClient(conn)
	return client
}
