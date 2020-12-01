package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fyne.io/fyne/widget"
	"github.com/inverse-inc/wireguard-go/binutils"
	"github.com/inverse-inc/wireguard-go/wgrpc"
	"github.com/inverse-inc/wireguard-go/ztn"
	"github.com/joho/godotenv"

	_ "net/http/pprof"
)

var rpc = wgrpc.WGRPCClient()

var messages = map[string]string{
	ztn.STATUS_CONNECTED:      "Ready to connect to peers",
	ztn.STATUS_ERROR:          "An error has occured",
	ztn.STATUS_FETCHING_PEERS: "Obtaining list of peers from central server",
	ztn.STATUS_NOT_READY:      "Starting tunnel",
}

func main() {
	if len(os.Args) > 1 {
		godotenv.Load(os.Args[1])
	}

	binutils.Setenv("WG_GUI_PID", os.Getenv("WG_GUI_PID"))
	binutils.Setenv("WG_CLI", "false")

	go binutils.CheckParentIsAlive(quit)

	go func() {
		//PPROF
		log.Println(http.ListenAndServe("localhost:6061", nil))
	}()

	setupExitSignals()
	SetupAPIClientGUI(func(runTunnel bool) {
		startTunnel(runTunnel)
	})
	quit()
}

func startTunnel(runTunnel bool) {
	go checkTunnelStatus()
	if runTunnel {
		go binutils.RunTunnel()
	}
}

func postRun() {
	fmt.Println("Tunnel was launched. Waiting for the end of this process")
	for {
		time.Sleep(1 * time.Second)
	}
}

func quit() {
	os.Exit(0)
}

func setupExitSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-sigs
		quit()
	}()
}

func checkTunnelStatus() {
	maxRpcFails := 30
	ctx := context.Background()
	started := time.Now()
	status := ""
	fails := 0
	for {
		statusReply, err := rpc.GetStatus(ctx, &wgrpc.StatusRequest{})
		if err != nil {
			if status == "" {
				fmt.Println("Failed to contact tunnel for initial status", err)
				if time.Since(started) > 1*time.Minute {
					statusLabel.SetText("Failed to start tunnel process")
				}
			} else if fails >= maxRpcFails {
				statusLabel.SetText("Too many failures communicating with RPC server. Tunnel seems to be dead. Please restart the client.")
				peersTableContainer.SetContent(widget.NewLabel(""))
			} else {
				fmt.Println("Failed to contact tunnel for status update")
				statusLabel.SetText("Tunnel seems to be inactive...")
				fails++
			}
		} else {
			fails = 0
			status = statusReply.Status
			if status == ztn.STATUS_ERROR {
				statusLabel.SetText(messages[status] + ": " + statusReply.LastError)
				restartBtn.Show()
				return
			} else {
				statusLabel.SetText(messages[status])
				UpdatePeers(ctx, rpc)
			}
		}

		time.Sleep(1 * time.Second)
	}
}
