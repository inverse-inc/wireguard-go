package ztn

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
	"golang.org/x/crypto/ssh/terminal"
)

var APIClient *unifiedapiclient.Client
var APIClientCtx context.Context

// TODO: replace with prompts or configuration
func SetupAPIClient() {
	server := sharedutils.EnvOrDefault("WG_SERVER", "")
	if server == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Server: ")
		server, _ = reader.ReadString('\n')
		server = strings.Trim(server, "\r\n")
	} else {
		fmt.Println("Using environment provided server:", server)
	}

	port := sharedutils.EnvOrDefault("WG_SERVER_PORT", "")
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

	username := sharedutils.EnvOrDefault("WG_USERNAME", "")
	if username == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Username: ")
		username, _ = reader.ReadString('\n')
		username = strings.Trim(username, "\r\n")
	} else {
		fmt.Println("Using environment provided username:", username)
	}

	fmt.Print("Enter Password for " + username + ": ")
	bytePassword, _ := terminal.ReadPassword(0)
	password := string(bytePassword)

	APIClientCtx = context.Background()
	APIClient = unifiedapiclient.New(APIClientCtx, username, password, "https", server, port)
}

func GetAPIClient() *unifiedapiclient.Client {
	if APIClient == nil {
		SetupAPIClient()
	}
	return APIClient
}
