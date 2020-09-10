package main

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"

	"fyne.io/fyne/app"
	"fyne.io/fyne/widget"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
)

var spacePlaceholder = "                          "

func SetupAPIClientGUI(callback func()) {
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
			setenv("WG_USERNAME", usernameEntry.Text)
			setenv("WG_PASSWORD", base64.StdEncoding.EncodeToString([]byte(passwordEntry.Text)))
			setenv("WG_SERVER", serverEntry.Text)
			setenv("WG_SERVER_PORT", serverPortEntry.Text)
			verifySslStr := "y"
			if !verifyServerEntry.Checked {
				verifySslStr = "n"
			}
			setenv("WG_SERVER_VERIFY_TLS", verifySslStr)
			
			w.SetContent(widget.NewLabel("Connecting..."))
			callback()
			//TODO implement check on a localhost running HTTP API that the wireguard agent should run
		}),
	))

	w.ShowAndRun()
}
