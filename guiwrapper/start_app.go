package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/container"
	"fyne.io/fyne/dialog"
	"fyne.io/fyne/widget"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/binutils"
	"github.com/inverse-inc/wireguard-go/util"
	"github.com/inverse-inc/wireguard-go/wgrpc"
	"github.com/inverse-inc/wireguard-go/ztn"
)

var spacePlaceholder = "                          "

var statusLabel *widget.Label
var bindTechniqueLabel = widget.NewLabel("N/A")

var peersScrollContainer = container.NewVScroll(widget.NewVBox())
var peersTableContainer = widget.NewCard("Peers", "", peersScrollContainer)
var peersTable = NewTable()
var peersTableHeadings = []string{"Host", "IP address", "State"}

var restartBtn *widget.Button

var w fyne.Window

func init() {
	peersScrollContainer.SetMinSize(fyne.Size{Height: 300, Width: 500})
	peersScrollContainer.Content = peersTable.GetContainer()
	peersScrollContainer.Direction = container.ScrollVerticalOnly
}

func Refresh() {
	w.Content().Refresh()
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
	Start(w, callback)

	w.SetCloseIntercept(func() {
		dialog.ShowCustomConfirm("PacketFence Zero Trust Client", "Minimize", "Exit", widget.NewVBox(widget.NewLabel("Exit or minimize the client?")), func(minimize bool) {
			if minimize {
				quit()
			} else {
				p, err := os.FindProcess(sharedutils.EnvOrDefaultInt(ztn.EnvGUIPID, 0))
				sharedutils.CheckError(err)
				util.KillProcess(p)
			}
		}, w)
	})

	w.ShowAndRun()
}

func Start(w fyne.Window, callback func(bool)) {
	var err error

	tab1 := container.NewTabItem("Connection", widget.NewHBox())
	tab2 := container.NewTabItem("Settings", widget.NewHBox())
	tabs := container.NewAppTabs(tab1)

	restartBtn = widget.NewButton("Restart", func() {
		_, err := rpc.Stop(context.Background(), &wgrpc.StopRequest{KillMasterProcess: true})
		if err != nil {
			fmt.Println("Failed to stop the tunnel", err)
		}
		Start(w, callback)
	})
	restartBtn.Hide()

	_, err = rpc.GetStatus(context.Background(), &wgrpc.StatusRequest{})
	if err != nil {
		tabs.Append(tab2)
		PromptCredentials(tabs, callback)
	} else {
		PostConnect(tabs)
		go checkTunnelStatus()
	}

	w.SetContent(tabs)

	Refresh()
}

func PromptCredentials(tabs *container.AppTabs, callback func(bool)) {
	connectionTab := tabs.Items[0]
	settingsTab := tabs.Items[1]

	serverEntry := widget.NewEntry()
	serverEntry.PlaceHolder = "ztn.example.com"
	serverEntry.Text = sharedutils.EnvOrDefault(ztn.EnvServer, "")

	serverPortEntry := widget.NewEntry()
	serverPortEntry.Text = sharedutils.EnvOrDefault(ztn.EnvServerPort, "9999")

	verifyServerEntry := widget.NewCheck("Verify server identity", func(bool) {})
	verifyServerEntry.Checked = (sharedutils.EnvOrDefault(ztn.EnvServerVerifyTLS, "true") == "true")

	usernameEntry := widget.NewEntry()
	usernameEntry.PlaceHolder = spacePlaceholder
	usernameEntry.Text = sharedutils.EnvOrDefault(ztn.EnvUsername, "")

	formError := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	formError.Hide()

	passwordEntry := NewPasswordField()
	passwordEntry.PlaceHolder = spacePlaceholder

	installRoutesFromServerEntry := widget.NewCheck("Install routes from server", func(bool) {})
	installRoutesFromServerEntry.Checked = (sharedutils.EnvOrDefault(ztn.EnvHonorRoutes, "true") == "true")

	preferedBindTechniqueEntry := widget.NewSelect([]string{
		string(ztn.BindNATPMP),
		string(ztn.BindSTUN),
		string(ztn.BindThroughPeer),
		string(ztn.BindUPNPIGD),
	}, func(string) {})
	preferedBindTechniqueEntry.SetSelected(sharedutils.EnvOrDefault(ztn.EnvBindTechnique, string(ztn.BindAutomatic)))

	failoverBindTechniqueEntry := widget.NewCheck("Automatically switch bind technique on failure", func(bool) {})
	failoverBindTechniqueEntry.Checked = (sharedutils.EnvOrDefault(ztn.EnvStaticBindTechnique, "false") == "false")

	setupDNSEntry := widget.NewCheck("Setup DNS on this system", func(bool) {})
	setupDNSEntry.Checked = (sharedutils.EnvOrDefault(ztn.EnvSetupDNS, "true") == "true")

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

		binutils.Setenv(ztn.EnvUsername, usernameEntry.Text)
		binutils.Setenv(ztn.EnvPassword, base64.StdEncoding.EncodeToString([]byte(passwordEntry.Text)))
		binutils.Setenv(ztn.EnvServer, serverEntry.Text)
		binutils.Setenv(ztn.EnvServerPort, serverPortEntry.Text)
		verifySslStr := "y"
		if !verifyServerEntry.Checked {
			verifySslStr = "n"
		}
		binutils.Setenv(ztn.EnvServerVerifyTLS, verifySslStr)

		honorRoutesStr := "true"
		if !installRoutesFromServerEntry.Checked {
			honorRoutesStr = "false"
		}
		binutils.Setenv(ztn.EnvHonorRoutes, honorRoutesStr)

		if preferedBindTechniqueEntry.Selected != string(ztn.BindAutomatic) {
			binutils.Setenv(ztn.EnvBindTechnique, preferedBindTechniqueEntry.Selected)
		}

		staticBindTechniqueStr := "false"
		if !failoverBindTechniqueEntry.Checked {
			staticBindTechniqueStr = "true"
		}
		binutils.Setenv(ztn.EnvStaticBindTechnique, staticBindTechniqueStr)

		setupDNSStr := "true"
		if !setupDNSEntry.Checked {
			setupDNSStr = "false"
		}
		binutils.Setenv(ztn.EnvSetupDNS, setupDNSStr)

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
	)

	settingsTab.Content = widget.NewVBox(
		installRoutesFromServerEntry,
		widget.NewHBox(
			widget.NewLabel("Bind technique"),
			preferedBindTechniqueEntry,
		),
		failoverBindTechniqueEntry,
		setupDNSEntry,
	)

	Refresh()
}

func PostConnect(tabs *container.AppTabs) {
	statusLabel = widget.NewLabel("Opening tunnel process")
	statusLabel.Wrapping = fyne.TextWrapWord
	tabs.Items[0].Content = widget.NewVBox(
		statusLabel,
		restartBtn,
		widget.NewHBox(widget.NewLabel("Bind Technique: "), bindTechniqueLabel),
		peersTableContainer,
	)
	if len(tabs.Items) > 1 {
		tabs.RemoveIndex(1)
	}
	Refresh()
}

func UpdatePeers(ctx context.Context, rpc wgrpc.WGServiceClient) {
	peers, err := rpc.GetPeers(ctx, &wgrpc.PeersRequest{})
	if err != nil {
		statusLabel.SetText("Failed to obtain peers from local wireguard server: " + err.Error())
		peersTable.Hide()
		return
	}

	peersTable.Show()

	sort.Slice(peers.Peers, func(i, j int) bool {
		h1 := strings.ToLower(peers.Peers[i].Hostname)
		h2 := strings.ToLower(peers.Peers[j].Hostname)
		if h1 == h2 {
			return peers.Peers[i].IpAddress < peers.Peers[j].IpAddress
		} else {
			return h1 < h2
		}
	})

	peersInfos := [][]string{}
	for _, peer := range peers.Peers {
		peersInfos = append(peersInfos, []string{peer.Hostname, peer.IpAddress, peer.Status})
	}

	peersTable.Update(
		peersTableHeadings,
		peersInfos,
	)

}
