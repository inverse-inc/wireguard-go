package ztn

import (
	"github.com/inverse-inc/packetfence/go/sharedutils"
	grpc "google.golang.org/grpc"
)

const PeerServiceServerPort = 6971

func ConnectPeerServiceClient(addr string) PeerServiceClient {
	conn, err := grpc.Dial(
		addr,
		grpc.WithInsecure(),
	)
	sharedutils.CheckError(err)
	client := NewPeerServiceClient(conn)
	return client
}
