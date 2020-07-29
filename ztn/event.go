package ztn

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/jcuga/golongpoll/go-client/glpclient"
)

type Event struct {
	Type string `json:"type"`
	Data gin.H  `json:"data"`
}

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func glpPublish(category string, e Event) error {
	d, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = http.Post(orchestrationServer+`/events/`+category, "application/json", bytes.NewReader(d))
	return err
}

func glpClient(category string) *glpclient.Client {
	u, _ := url.Parse(orchestrationServer + `/events`)
	c := glpclient.NewClient(u, category)
	c.LoggingEnabled = sharedutils.EnvOrDefault("LOG_LEVEL", "") == "debug"
	return c
}
