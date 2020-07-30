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
	}

	username := sharedutils.EnvOrDefault("WG_USERNAME", "")
	if username == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Username: ")
		username, _ = reader.ReadString('\n')
		username = strings.Trim(username, "\r\n")
	}

	fmt.Print("Enter Password: ")
	bytePassword, _ := terminal.ReadPassword(0)
	password := string(bytePassword)

	APIClientCtx = context.Background()
	APIClient = unifiedapiclient.New(APIClientCtx, username, password, "https", server, "9999")
}

func GetAPIClient() *unifiedapiclient.Client {
	if APIClient == nil {
		SetupAPIClient()
	}
	return APIClient
}
