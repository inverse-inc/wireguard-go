// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"gortc.io/stun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

var privKey = sharedutils.EnvOrDefault("PRIV_KEY", "")
var peerPubKey = sharedutils.EnvOrDefault("PEER_PUB_KEY", "")

func printUsage() {
	fmt.Printf("usage:\n")
	fmt.Printf("%s [-f/--foreground] INTERFACE-NAME\n", os.Args[0])
}

func warning() {
	if runtime.GOOS != "linux" || os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
		return
	}

	fmt.Fprintln(os.Stderr, "┌───────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                   │")
	fmt.Fprintln(os.Stderr, "│   Running this software on Linux is unnecessary,  │")
	fmt.Fprintln(os.Stderr, "│   because the Linux kernel has built-in first     │")
	fmt.Fprintln(os.Stderr, "│   class support for WireGuard, which will be      │")
	fmt.Fprintln(os.Stderr, "│   faster, slicker, and better integrated. For     │")
	fmt.Fprintln(os.Stderr, "│   information on installing the kernel module,    │")
	fmt.Fprintln(os.Stderr, "│   please visit: <https://wireguard.com/install>.  │")
	fmt.Fprintln(os.Stderr, "│                                                   │")
	fmt.Fprintln(os.Stderr, "└───────────────────────────────────────────────────┘")
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("wireguard-go v%s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <Jason@zx2c4.com>.\n", device.WireGuardGoVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

	var foreground bool
	var interfaceName string
	if len(os.Args) < 2 || len(os.Args) > 3 {
		printUsage()
		return
	}

	switch os.Args[1] {

	case "-f", "--foreground":
		foreground = true
		if len(os.Args) != 3 {
			printUsage()
			return
		}
		interfaceName = os.Args[2]

	default:
		foreground = false
		if len(os.Args) != 2 {
			printUsage()
			return
		}
		interfaceName = os.Args[1]
	}

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "debug":
			return device.LogLevelDebug
		case "info":
			return device.LogLevelInfo
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelInfo
	}()

	// open TUN device (or use supplied fd)

	tun, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = syscall.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)

	logger.Debug.Println("Debug log enabled")

	if err != nil {
		logger.Error.Println("Failed to create TUN device:", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()

	if err != nil {
		logger.Error.Println("UAPI listen error:", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tun.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Error.Println("Failed to determine executable:", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Error.Println("Failed to daemonize:", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	device := device.NewDevice(tun, logger)

	logger.Info.Println("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Error.Println("Failed to listen on uapi socket:", err)
		os.Exit(ExitSetupFailed)
	}

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

	setConfig(device, "listen_port", "6969")
	setConfig(device, "private_key", privKey)

	logger.Info.Println("UAPI listener started")

	go startStun(device)

	// wait for program to terminate

	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

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

func startStun(device *device.Device) {
	const udp = "udp"
	const pingMsg = "ping"

	wgConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6969})
	if err != nil {
		panic(err)
	}

	srvAddr, err := net.ResolveUDPAddr(udp, "srv.semaan.ca:3478")
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP(udp, nil)
	if err != nil {
		panic(err)
	}

	defer conn.Close()

	log.Printf("Listening on %s\n", conn.LocalAddr())

	var publicAddr stun.XORMappedAddress
	var peerAddr *net.UDPAddr

	messageChan := make(chan *pkt)
	listen(conn, messageChan)
	listen(wgConn, messageChan)
	var peerAddrChan <-chan string

	keepalive := time.Tick(500 * time.Millisecond)
	keepaliveMsg := pingMsg

	a := strings.Split(conn.LocalAddr().String(), ":")
	var localPeerAddr = "127.0.0.1:" + a[len(a)-1]

	for {
		select {
		case message, ok := <-messageChan:
			if !ok {
				return
			}

			switch {
			case stun.IsMessage(message.message):
				m := new(stun.Message)
				m.Raw = message.message
				decErr := m.Decode()
				if decErr != nil {
					log.Println("decode:", decErr)
					break
				}
				var xorAddr stun.XORMappedAddress
				if getErr := xorAddr.GetFrom(m); getErr != nil {
					log.Println("getFrom:", getErr)
					break
				}

				if publicAddr.String() != xorAddr.String() {
					log.Printf("My public address: %s\n", xorAddr)
					publicAddr = xorAddr

					peerAddrChan = getPeerAddr()
				}
				//TODO: this is very inneficient, change this
			case string(message.message) == pingMsg:
				fmt.Println("Received ping")

			default:
				if message.raddr.String() == "127.0.0.1:6969" {
					n := len(message.message)
					fmt.Printf("send to WG server: [%s]: %d bytes\n", peerAddr, n)
					send(message.message, conn, peerAddr)
				} else {
					n := len(message.message)
					fmt.Printf("send to WG server: [%s]: %d bytes\n", wgConn.RemoteAddr(), n)
					wgConn.Write(message.message)
				}

			}

		case peerStr := <-peerAddrChan:
			peerAddr, err = net.ResolveUDPAddr(udp, peerStr)
			if err != nil {
				log.Fatalln("resolve peeraddr:", err)
			}
			conf := `replace_peers=true
`
			conf += fmt.Sprintf("public_key=%s\n", peerPubKey)
			conf += fmt.Sprintf("endpoint=%s", localPeerAddr)
			conf += `
replace_allowed_ips=true
allowed_ip=0.0.0.0/0`

			fmt.Println(conf)

			setConfigMulti(device, conf)

		case <-keepalive:
			// Keep NAT binding alive using STUN server or the peer once it's known
			if peerAddr == nil {
				err = sendBindingRequest(conn, srvAddr)
			} else {
				err = sendStr(keepaliveMsg, conn, peerAddr)
			}

			if err != nil {
				log.Fatalln("keepalive:", err)
			}

		}
	}
}

type pkt struct {
	raddr   *net.UDPAddr
	message []byte
}

func listen(conn *net.UDPConn, messages chan *pkt) {
	go func() {
		for {
			buf := make([]byte, 1024)

			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				close(messages)
				return
			}
			buf = buf[:n]

			messages <- &pkt{raddr: raddr, message: buf}
		}
	}()
}

func sendBindingRequest(conn *net.UDPConn, addr *net.UDPAddr) error {
	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	err := send(m.Raw, conn, addr)
	if err != nil {
		return fmt.Errorf("binding: %v", err)
	}

	return nil
}

func send(msg []byte, conn *net.UDPConn, addr *net.UDPAddr) error {
	_, err := conn.WriteToUDP(msg, addr)
	if err != nil {
		return fmt.Errorf("send: %v", err)
	}

	return nil
}

func sendStr(msg string, conn *net.UDPConn, addr *net.UDPAddr) error {
	return send([]byte(msg), conn, addr)
}

func getPeerAddr() <-chan string {
	result := make(chan string)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		log.Println("Enter remote peer address:")
		peer, _ := reader.ReadString('\n')
		result <- strings.Trim(peer, " \r\n")
	}()

	return result
}

func setConfig(device *device.Device, k, v string) {
	device.IpcSetOperation(bufio.NewReader(bytes.NewBufferString(fmt.Sprintf("%s=%s", k, v))))
}

func setConfigMulti(device *device.Device, conf string) {
	device.IpcSetOperation(bufio.NewReader(bytes.NewBufferString(conf)))
}
