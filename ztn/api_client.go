package ztn

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"fyne.io/fyne/app"
	"fyne.io/fyne/widget"

	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
)

var APIClient *unifiedapiclient.Client
var APIClientCtx context.Context

// TODO: replace with prompts or configuration
func SetupAPIClientCLI() {
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

	verifySslStr := sharedutils.EnvOrDefault("WG_SERVER_VERIFY_TLS", "")
	verifySsl := true
	if verifySslStr == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Verify TLS identity of server? (Y/n): ")
		verifySslStr, _ = reader.ReadString('\n')
		verifySslStr = strings.Trim(verifySslStr, "\r\n")
	} else {
		fmt.Println("Using environment provided server verify TLS:", verifySslStr)
	}

	if verifySslStr == "" {
		verifySsl = true
	} else {
		verifySslStr = strings.TrimSpace(verifySslStr)
		verifySslStr = strings.ToLower(verifySslStr)
		verifySsl = (verifySslStr == "y" || verifySslStr == "yes")
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
	password := ReadPassword()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySsl},
		},
	}
	unifiedapiclient.SetHTTPClient(httpClient)

	APIClientCtx = log.LoggerNewContext(context.Background())
	APIClient = unifiedapiclient.New(APIClientCtx, username, password, "https", server, port)

	APIClient.URILogDebug = true
}

var spacePlaceholder = "                          "

func SetupAPIClientGUI() {
	a := app.New()
	w := a.NewWindow("Wireguard client")

	serverEntry := widget.NewEntry()
	serverEntry.PlaceHolder = "ztn.example.com"
	serverEntry.Text = sharedutils.EnvOrDefault("WG_SERVER", "")

	serverPortEntry := widget.NewEntry()
	serverPortEntry.Text = "9999"
	serverEntry.Text = sharedutils.EnvOrDefault("WG_SERVER_PORT", "")

	verifyServerEntry := widget.NewCheck("Verify server identity", func(bool) {})
	verifyServerEntry.Checked = (sharedutils.EnvOrDefault("WG_SERVER_VERIFY_TLS", "true") == "true")

	usernameEntry := widget.NewEntry()
	usernameEntry.PlaceHolder = spacePlaceholder
	usernameEntry.Text = sharedutils.EnvOrDefault("WG_USERNAME", "")

	passwordEntry := widget.NewEntry()
	passwordEntry.Password = true
	passwordEntry.PlaceHolder = spacePlaceholder

	w.SetContent(widget.NewVBox(
		widget.NewLabel("Wireguard client configuration"),
		widget.NewHBox(
			widget.NewLabel("Server"),
			serverEntry,
		),
		widget.NewHBox(
			widget.NewLabel("Server port"),
			serverPortEntry,
		),
		widget.NewHBox(
			verifyServerEntry,
		),
		widget.NewHBox(
			widget.NewLabel("Username"),
			usernameEntry,
		),
		widget.NewHBox(
			widget.NewLabel("Password"),
			passwordEntry,
		),
		widget.NewButton("Connect", func() {
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyServerEntry.Checked},
				},
			}
			unifiedapiclient.SetHTTPClient(httpClient)

			APIClientCtx = log.LoggerNewContext(context.Background())
			APIClient = unifiedapiclient.New(APIClientCtx, usernameEntry.Text, passwordEntry.Text, "https", serverEntry.Text, serverPortEntry.Text)

			APIClient.URILogDebug = true
			a.Quit()
		}),
	))

	w.ShowAndRun()
}

func GetAPIClient() *unifiedapiclient.Client {
	if APIClient == nil {
		if sharedutils.EnvOrDefault("WG_CLI", "false") == "true" {
			SetupAPIClientCLI()
		} else {
			SetupAPIClientGUI()
		}
	}
	return APIClient
}
