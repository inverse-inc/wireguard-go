package main

import (
	"encoding/base64"
	"fmt"
	"time"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/widget"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/util"
)

var spacePlaceholder = "                          "

var statusLabel *widget.Label
var peersTable *widget.Card

func SetupAPIClientGUI(callback func()) {
	a := app.New()

	icon, err := fyne.LoadResourceFromPath("logo.png")
	if err != nil {
		fmt.Println("Unable to find the app icon")
	} else {
		a.SetIcon(icon)
	}

	w := a.NewWindow(util.AppName)

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

	formError := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	formError.Hide()

	w.SetContent(widget.NewVBox(
		formError,
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

			showFormError := func(msg string) {
				formError.SetText(msg)
				formError.Show()
			}

			if usernameEntry.Text == "" {
				showFormError("You must enter a username")
				return
			}

			if passwordEntry.Text == "" {
				showFormError("You must enter a password")
				return
			}

			if serverEntry.Text == "" {
				showFormError("You must enter a server to connect to")
				return
			}

			setenv("WG_USERNAME", usernameEntry.Text)
			setenv("WG_PASSWORD", base64.StdEncoding.EncodeToString([]byte(passwordEntry.Text)))
			setenv("WG_SERVER", serverEntry.Text)
			setenv("WG_SERVER_PORT", serverPortEntry.Text)
			verifySslStr := "y"
			if !verifyServerEntry.Checked {
				verifySslStr = "n"
			}
			setenv("WG_SERVER_VERIFY_TLS", verifySslStr)

			PostConnect(w)
			callback()
		}),
	))

	w.ShowAndRun()
}

func PostConnect(w fyne.Window) {
	statusLabel = widget.NewLabel("Opening tunnel process")
	peersTable = widget.NewCard("Peers", "", widget.NewVBox())
	UpdatePeers()
	w.SetContent(widget.NewVBox(statusLabel, peersTable))
}

func UpdatePeers() {
	peersTable.SetContent(makeTable(
		[]string{"IP address", "State"},
		[][]string{
			[]string{"192.168.69.1", fmt.Sprint("bouzin", time.Now().Unix())},
			[]string{"a", "bouzin"},
			[]string{"192.168.69.100", "bouzinsadf,asfosaidfpo sadifopsa dfiosaidopf394583i4u"},
		},
	))
}
