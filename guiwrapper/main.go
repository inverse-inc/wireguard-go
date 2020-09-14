package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/inverse-inc/wireguard-go/wgrpc"
	"github.com/inverse-inc/wireguard-go/ztn/rpc"
)

var messages = map[string]string{
	wgrpc.STATUS_CONNECTED: "Connected",
	wgrpc.STATUS_ERROR:     "An error has occured",
	wgrpc.STATUS_NOT_READY: "Starting tunnel",
}

var wireguardCmd *exec.Cmd
var wgenv *os.File

func main() {
	fmt.Println("Starting up")
	setenv("WG_GUI_PID", fmt.Sprintf("%d", os.Getpid()))

	go startTray()
	setupExitSignals()
	SetupAPIClientGUI(func() {
		go checkTunnelStatus()
		run()
		postRun()
		quit()
	})
	quit()
}

func postRun() {
	fmt.Println("Tunnel was launched. Waiting for the end of this process")
	for {
		time.Sleep(1 * time.Second)
	}
}

func startTray() {
	var cmd *exec.Cmd
	if wgenv != nil {
		cmd = exec.Command(binPath("traywrapper"), wgenv.Name())
	} else {
		cmd = exec.Command(binPath("traywrapper"))
	}
	runCmd(cmd)
	fmt.Println("Tray has exited, exiting")
	quit()
}

func quit() {
	if wgenv != nil {
		fmt.Println("Cleaning up environment file:", wgenv.Name())
		os.Remove(wgenv.Name())
	}
	os.Exit(0)
}

func setupExitSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		quit()
	}()
}

func checkTunnelStatus() {
	maxRpcFails := 5
	ctx := context.Background()
	rpc := rpc.WGRPCClient()
	started := time.Now()
	status := ""
	fails := 0
	for {
		statusReply, err := rpc.GetStatus(ctx, &wgrpc.StatusRequest{})
		if err != nil {
			if status == "" {
				fmt.Println("Failed to contact tunnel for initial status")
				if time.Since(started) > 1*time.Minute {
					statusLabel.SetText("Failed to start tunnel process")
				}
			} else if fails >= maxRpcFails {
				statusLabel.SetText("Too many failures communicating with RPC server. Tunnel seems to be dead.")
			} else {
				fmt.Println("Failed to contact tunnel for status update")
				statusLabel.SetText("Tunnel seems to be inactive...")
				fails++
			}
		} else {
			fails = 0
			status = statusReply.Status
			if status == wgrpc.STATUS_ERROR {
				statusLabel.SetText(messages[status] + ": " + statusReply.LastError)
			} else {
				statusLabel.SetText(messages[status])
			}
		}

		time.Sleep(1 * time.Second)
	}
}
