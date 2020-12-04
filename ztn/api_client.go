package ztn

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
)

var APIClient *unifiedapiclient.Client
var APIClientCtx context.Context

// TODO: replace with prompts or configuration
func SetupAPIClientCLI() {
	server := sharedutils.EnvOrDefault(EnvServer, "")
	if server == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Server: ")
		server, _ = reader.ReadString('\n')
		server = strings.Trim(server, "\r\n")
	} else {
		fmt.Println("Using environment provided server:", server)
	}

	port := sharedutils.EnvOrDefault(EnvServerPort, "")
	if port == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Server port (default 9999): ")
		port, _ = reader.ReadString('\n')
		port = strings.Trim(port, "\r\n")

		if port == "" {
			port = "9999"
		}
	} else {
		fmt.Println("Using environment provided server port:", port)
	}

	verifySslStr := sharedutils.EnvOrDefault(EnvServerVerifyTLS, "")
	if verifySslStr == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Verify TLS identity of server? (Y/n): ")
		verifySslStr, _ = reader.ReadString('\n')
		verifySslStr = strings.Trim(port, "\r\n")

		if verifySslStr == "" {
			verifySslStr = "y"
		}
	} else {
		fmt.Println("Using environment provided server verify TLS:", verifySslStr)
	}

	username := sharedutils.EnvOrDefault(EnvUsername, "")
	if username == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Username: ")
		username, _ = reader.ReadString('\n')
		username = strings.Trim(username, "\r\n")
	} else {
		fmt.Println("Using environment provided username:", username)
	}

	fmt.Print("Enter Password for " + username + ": ")
	password := ReadPassword()

	setupAPIClientFromData(username, password, server, port, verifySslStr)
}

func mustGetenv(k string) string {
	if v := os.Getenv(k); v == "" {
		panic("Key " + k + " is empty in the enviorment")
	} else {
		return v
	}
}

func SetupAPIClientEnv() {
	pass, err := base64.StdEncoding.DecodeString(mustGetenv(EnvPassword))
	sharedutils.CheckError(err)
	setupAPIClientFromData(mustGetenv(EnvUsername), string(pass), mustGetenv(EnvServer), mustGetenv(EnvServerPort), mustGetenv(EnvServerVerifyTLS))
}

func setupAPIClientFromData(username, password, serverName, serverPort, verifySslStr string) {
	verifySsl := (verifySslStr == "y" || verifySslStr == "yes")
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySsl},
		},
	}

	unifiedapiclient.SetHTTPClient(httpClient)
	APIClientCtx = log.LoggerNewContext(context.Background())
	APIClient = unifiedapiclient.New(APIClientCtx, username, password, "https", serverName, serverPort)
	APIClient.URILogDebug = true
}

func GetAPIClient() *unifiedapiclient.Client {
	if APIClient == nil {
		if RunningInCLI() && (sharedutils.EnvOrDefault(EnvCLIInterractive, "true") == "true") {
			SetupAPIClientCLI()
		} else {
			SetupAPIClientEnv()
		}
	}
	return APIClient
}
