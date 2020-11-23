package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/container"
	"fyne.io/fyne/widget"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/binutils"
	"github.com/inverse-inc/wireguard-go/util"
	"github.com/inverse-inc/wireguard-go/wgrpc"
)

var spacePlaceholder = "                          "

var statusLabel *widget.Label
var peersTable *widget.Card
var reconnectBtn *widget.Button

var w fyne.Window

func Refresh() {
	//w.Content().Refresh()
}

func SetupAPIClientGUI(callback func(bool)) {
	a := app.New()

	icon, err := fyne.LoadResourceFromPath("logo.png")
	if err != nil {
		fmt.Println("Unable to find the app icon")
	} else {
		a.SetIcon(icon)
	}

	w = a.NewWindow(util.AppName)
	tab1 := container.NewTabItem("Connection", widget.NewHBox())
	tab2 := container.NewTabItem("Settings", widget.NewHBox())
	tabs := container.NewAppTabs(tab1)

	reconnectBtn = widget.NewButton("Reconnect", func() {
		reconnectBtn.Hide()
		statusLabel.SetText("Reconnecting")
		go binutils.RunTunnel()
	})
	reconnectBtn.Hide()

	_, err = rpc.GetStatus(context.Background(), &wgrpc.StatusRequest{})
	if err != nil {
		tabs.Append(tab2)
		PromptCredentials(tabs, callback)
	} else {
		PostConnect(tabs)
		go checkTunnelStatus()
	}

	w.SetContent(tabs)

	w.ShowAndRun()
}

func PromptCredentials(tabs *container.AppTabs, callback func(bool)) {
	connectionTab := tabs.Items[0]
	settingsTab := tabs.Items[1]

	serverEntry := widget.NewEntry()
	serverEntry.PlaceHolder = "ztn.example.com"
	serverEntry.Text = sharedutils.EnvOrDefault("WG_SERVER", "")

	serverPortEntry := widget.NewEntry()
	serverPortEntry.Text = sharedutils.EnvOrDefault("WG_SERVER_PORT", "9999")

	verifyServerEntry := widget.NewCheck("Verify server identity", func(bool) {})
	verifyServerEntry.Checked = (sharedutils.EnvOrDefault("WG_SERVER_VERIFY_TLS", "true") == "true")

	usernameEntry := widget.NewEntry()
	usernameEntry.PlaceHolder = spacePlaceholder
	usernameEntry.Text = sharedutils.EnvOrDefault("WG_USERNAME", "")

	formError := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	formError.Hide()

	passwordEntry := NewPasswordField()
	passwordEntry.PlaceHolder = spacePlaceholder

	installRoutesFromServerEntry := widget.NewCheck("Install routes from server", func(bool) {})
	installRoutesFromServerEntry.Checked = true

	connect := func() {

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

		binutils.Setenv("WG_USERNAME", usernameEntry.Text)
		binutils.Setenv("WG_PASSWORD", base64.StdEncoding.EncodeToString([]byte(passwordEntry.Text)))
		binutils.Setenv("WG_SERVER", serverEntry.Text)
		binutils.Setenv("WG_SERVER_PORT", serverPortEntry.Text)
		verifySslStr := "y"
		if !verifyServerEntry.Checked {
			verifySslStr = "n"
		}
		binutils.Setenv("WG_SERVER_VERIFY_TLS", verifySslStr)

		honorRoutesStr := "true"
		if !installRoutesFromServerEntry.Checked {
			honorRoutesStr = "false"
		}
		binutils.Setenv("WG_HONOR_ROUTES", honorRoutesStr)

		PostConnect(tabs)
		callback(true)
	}

	passwordEntry.onEnter = connect

	connectionTab.Content = widget.NewVBox(
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
		widget.NewButton("Connect", connect),
		reconnectBtn,
	)

	settingsTab.Content = widget.NewVBox(
		widget.NewHBox(
			installRoutesFromServerEntry,
		),
	)

	Refresh()
}

func PostConnect(tabs *container.AppTabs) {
	statusLabel = widget.NewLabel("Opening tunnel process")
	peersTable = widget.NewCard("Peers", "", widget.NewVBox())
	tabs.Items[0].Content = widget.NewVBox(statusLabel, reconnectBtn, peersTable)
	if len(tabs.Items) > 1 {
		tabs.RemoveIndex(1)
	}
	Refresh()
}

func UpdatePeers(ctx context.Context, rpc wgrpc.WGServiceClient) {
	peers, err := rpc.GetPeers(ctx, &wgrpc.PeersRequest{})
	if err != nil {
		peersTable.SetContent(widget.NewLabel("Failed to obtain peers from local wireguard server: " + err.Error()))
		return
	}

	sort.Slice(peers.Peers, func(i, j int) bool {
		return peers.Peers[i].Hostname < peers.Peers[j].Hostname
	})

	peersInfos := [][]string{}
	for _, peer := range peers.Peers {
		peersInfos = append(peersInfos, []string{peer.Hostname, peer.IpAddress, peer.Status})
	}

	peersTable.SetContent(makeTable(
		[]string{"Host", "IP address", "State"},
		peersInfos,
	))
}
