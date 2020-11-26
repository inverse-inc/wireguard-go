package peerrpc

import (
	"fmt"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	grpc "google.golang.org/grpc"
)

func Client() PeerServiceClient {
	// TODO move this to the WG interface
	conn, err := grpc.Dial(
		fmt.Sprintf("127.0.0.1:%d", 6970),
		grpc.WithInsecure(),
	)
	sharedutils.CheckError(err)
	client := NewPeerServiceClient(conn)
	return client
}
