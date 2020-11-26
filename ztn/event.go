package ztn

import (
	"crypto/tls"
	"encoding/json"
	"net/http"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient/glpclient"
)

type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func GLPPublish(category string, e Event) error {
	err := GetAPIClient().CallWithBody(APIClientCtx, "POST", "/api/v1/remote_clients/events/"+category, e, &unifiedapiclient.DummyReply{})
	return err
}

func GLPClient(category string) *glpclient.Client {
	apiClient := GetAPIClient()
	c := glpclient.NewClient(apiClient, "/api/v1/remote_clients/events", category)
	c.LoggingEnabled = sharedutils.EnvOrDefault("LOG_LEVEL", "") == "debug"
	return c
}

func GLPPrivateClient(priv, pub, serverPub [32]byte) *glpclient.Client {
	apiClient := GetAPIClient()
	c := glpclient.NewClient(apiClient, "/api/v1/remote_clients/my_events", "")
	c.LoggingEnabled = sharedutils.EnvOrDefault("LOG_LEVEL", "") == "debug"
	c.SetPrivateMode(priv, pub, serverPub)
	return c
}
