package ztn

import (
	"crypto/tls"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient/glpclient"
)

type Event struct {
	Type string `json:"type"`
	Data gin.H  `json:"data"`
}

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func glpPublish(category string, e Event) error {
	err := GetAPIClient().CallWithBody(APIClientCtx, "POST", "/api/v1/remote_clients/events/"+category, e, &unifiedapiclient.DummyReply{})
	return err
}

func glpClient(category string) *glpclient.Client {
	apiClient := GetAPIClient()
	c := glpclient.NewClient(apiClient, "/api/v1/remote_clients/events", category)
	c.LoggingEnabled = sharedutils.EnvOrDefault("LOG_LEVEL", "") == "debug"
	return c
}
