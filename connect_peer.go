package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func startStun(device *device.Device) {
	const udp = "udp"
	const pingMsg = "ping"

	wgConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6969})
	if err != nil {
		panic(err)
	}

	srvAddr, err := net.ResolveUDPAddr(udp, "stun.l.google.com:19302")
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
	var peerPubKey string

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
			case string(message.message) == pingMsg:
				logger.Debug.Println("Received ping from", peerAddr)

			default:
				if message.raddr.String() == "127.0.0.1:6969" {
					n := len(message.message)
					logger.Debug.Println("send to WG server: [%s]: %d bytes\n", peerAddr, n)
					send(message.message, conn, peerAddr)
				} else {
					n := len(message.message)
					logger.Debug.Println("send to WG server: [%s]: %d bytes\n", wgConn.RemoteAddr(), n)
					wgConn.Write(message.message)
				}

			}

		case peerStr := <-peerAddrChan:
			reader := bufio.NewReader(os.Stdin)
			log.Println("Enter remote peer public key:")
			peer, _ := reader.ReadString('\n')
			peerPubKey = keyToHex(strings.Trim(peer, " \r\n"))

			reader = bufio.NewReader(os.Stdin)
			log.Println("Enter remote peer wireguard IP:")
			peerIP, _ := reader.ReadString('\n')
			peerIP = strings.Trim(peerIP, " \r\n")

			peerAddr, err = net.ResolveUDPAddr(udp, peerStr)
			if err != nil {
				log.Fatalln("resolve peeraddr:", err)
			}
			conf := ""
			conf += fmt.Sprintf("public_key=%s\n", peerPubKey)
			conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
			conf += "replace_allowed_ips=true\n"
			conf += fmt.Sprintf("allowed_ip=%s/32\n", peerIP)

			fmt.Println(conf)

			setConfigMulti(device, conf)

			// Ready to read another peer
			go startStun(device)

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
