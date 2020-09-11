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
	"github.com/inverse-inc/wireguard-go/ztn"
)

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
	rpc := ztn.WGRPCClient()
	started := time.Now()
	status := ""
	fails := 0
	for {
		statusReply, err := rpc.GetStatus(ctx, &wgrpc.StatusRequest{})
		if err != nil {
			if status == "" {
				fmt.Println("Failed to contact tunnel for initial status")
				if time.Since(started) > 1*time.Minute {
					fmt.Println("Waited too long for tunnel to start. Exiting")
					quit()
				}
			} else if fails >= maxRpcFails {
				fmt.Println("Too many failures communicating with RPC server. Tunnel seems to be dead. Exiting.")
				quit()
			} else {
				fmt.Println("Failed to contact tunnel for status update")
				statusLabel.SetText("Tunnel seems to be inactive...")
				fails++
			}
		} else {
			fails = 0
			status = statusReply.Status
			statusLabel.SetText("Connected...")
		}

		time.Sleep(1 * time.Second)
	}
}
