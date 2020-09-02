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

	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ipc"

	"github.com/inverse-inc/wireguard-go/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var logger *device.Logger

func main() {
	if len(os.Args) != 2 {
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	logger = device.NewLogger(
		device.LogLevelInfo,
		fmt.Sprintf("(%s) ", interfaceName),
	)
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
}
