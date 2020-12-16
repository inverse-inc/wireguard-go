// +build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	godnschange "github.com/inverse-inc/go-dnschange"
	"github.com/inverse-inc/wireguard-go/binutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ipc"
	"github.com/inverse-inc/wireguard-go/outputlog"
	"github.com/inverse-inc/wireguard-go/tun"
	"github.com/inverse-inc/wireguard-go/util"
	"github.com/joho/godotenv"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var logger *device.Logger
var DNSChange *godnschange.DNSStruct

func main() {
	defer binutils.CapturePanic()

	outputlog.RedirectOutputToFile("C:\\Program Files\\PacketFence-Zero-Trust-Client\\wireguard.log")

	godotenv.Load(os.Args[1])

	if len(os.Args) > 2 && os.Args[2] == "--master" {
		logger = device.NewLogger(
			device.LogLevelInfo,
			fmt.Sprintf("(%s) ", "Master"),
		)

		os.Setenv("LOG_LEVEL", "info")
		setMasterProcess()
		DNSChange = StartDNS()
		go checkParentIsAlive()

		for {
			binutils.RunTunnelFG(os.Args[1])
		}
	} else {
		interfaceName := "wg0"

		logger = device.NewLogger(
			device.LogLevelInfo,
			fmt.Sprintf("(%s) ", interfaceName),
		)

		os.Setenv("LOG_LEVEL", "info")

		logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)
		logger.Debug.Println("Debug log enabled")

		tun, err := tun.CreateTUN(interfaceName, 0)
		if err == nil {
			realInterfaceName, err2 := tun.Name()
			if err2 == nil {
				interfaceName = realInterfaceName
			}
		} else {
			logger.Error.Println("Failed to create TUN device:", err)
			os.Exit(ExitSetupFailed)
		}

		device := device.NewDevice(tun, logger)
		device.Up()
		logger.Info.Println("Device started")

		uapi, err := ipc.UAPIListen(interfaceName)
		if err != nil {
			logger.Error.Println("Failed to listen on uapi socket:", err)
			os.Exit(ExitSetupFailed)
		}

		errs := make(chan error)
		term := make(chan os.Signal, 1)

		go func() {
			for {
				conn, err := uapi.Accept()
				if err != nil {
					errs <- err
					return
				}
				go device.IpcHandle(conn)
			}
		}()
		logger.Info.Println("UAPI listener started")

		startInverse(interfaceName, device)

		// wait for program to terminate

		signal.Notify(term, os.Interrupt)
		signal.Notify(term, os.Kill)
		signal.Notify(term, syscall.SIGTERM)

		select {
		case <-term:
		case <-errs:
		case <-device.Wait():
		}

		// clean up

		uapi.Close()
		device.Close()

		logger.Info.Println("Shutting down")

		quit()
	}
}

func checkParentIsAlive() {
	util.CheckGUIIsAliveWindows(quit)
}
