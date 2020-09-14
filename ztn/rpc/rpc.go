package rpc

import (
	"fmt"
	"net"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/wgrpc"
	"google.golang.org/grpc"
)

const ServerPort = 6970

var WGRPCServer *wgrpc.WGServiceServerHandler

func StartRPC() {
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ServerPort))
	sharedutils.CheckError(err)
	grpcServer := grpc.NewServer()
	WGRPCServer = wgrpc.NewWGServiceServerHandler()
	wgrpc.RegisterWGServiceServer(grpcServer, WGRPCServer)
	grpcServer.Serve(lis)
}

func WGRPCClient() wgrpc.WGServiceClient {
	conn, err := grpc.Dial(
		fmt.Sprintf("127.0.0.1:%d", ServerPort),
		grpc.WithInsecure(),
	)
	sharedutils.CheckError(err)
	client := wgrpc.NewWGServiceClient(conn)
	return client
}
