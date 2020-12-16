package ztn

import (
	"fmt"
	"net"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const PeerServiceServerPort = 12676

func ConnectPeerServiceClient(addr string) (PeerServiceClient, *grpc.ClientConn) {
	conn, err := grpc.Dial(
		addr,
		grpc.WithInsecure(),
	)
	sharedutils.CheckError(err)
	client := NewPeerServiceClient(conn)
	return client, conn
}

func StartPeerServiceRPC(ip net.IP, logger *device.Logger, profile Profile) {
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, PeerServiceServerPort))
	sharedutils.CheckError(err)
	grpcServer := grpc.NewServer()

	PeerServer := NewPeerServiceServerHandler(logger, profile)
	RegisterPeerServiceServer(grpcServer, PeerServer)

	reflection.Register(grpcServer)
	grpcServer.Serve(lis)
}
