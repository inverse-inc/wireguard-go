package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/jcuga/golongpoll/go-client/glpclient"
	"golang.zx2c4.com/wireguard/device"
	"gortc.io/stun"
)

const server = "http://srv.semaan.ca:6969"

type Peer struct {
	WireguardIP net.IP `json:"wireguard_ip"`
	PublicKey   string `json:"public_key"`
}

type Profile struct {
	WireguardIP      net.IP   `json:"wireguard_ip"`
	WireguardNetmask int      `json:"wireguard_netmask"`
	PublicKey        string   `json:"public_key"`
	PrivateKey       string   `json:"private_key"`
	AllowedPeers     []string `json:"allowed_peers"`
}

type Event struct {
	Type string `json:"type"`
	Data gin.H  `json:"data"`
}

func glpPublish(category string, e Event) error {
	d, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = http.Post(server+`/events/`+category, "application/json", bytes.NewReader(d))
	return err
}

func glpClient(category string) *glpclient.Client {
	u, _ := url.Parse(server + `/events`)
	c := glpclient.NewClient(u, category)
	return c
}

func startStun(device *device.Device, profile Profile, peer Peer) {
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

					go func() {
						for {
							glpPublish(buildP2PKey(profile.PublicKey, peer.PublicKey), Event{Type: "public_endpoint", Data: gin.H{"id": profile.PublicKey, "public_endpoint": publicAddr.String()}})
							time.Sleep(10 * time.Second)
						}
					}()

					peerAddrChan = getPeerAddr(profile.PublicKey, peer.PublicKey)
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
			peerAddr, err = net.ResolveUDPAddr(udp, peerStr)
			if err != nil {
				log.Fatalln("resolve peeraddr:", err)
			}
			conf := ""
			conf += fmt.Sprintf("public_key=%s\n", keyToHex(peer.PublicKey))
			conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
			conf += "replace_allowed_ips=true\n"
			conf += fmt.Sprintf("allowed_ip=%s/32\n", peer.WireguardIP.String())

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

func getPeerAddr(myID string, peerID string) <-chan string {
	result := make(chan string)

	p2pk := buildP2PKey(myID, peerID)

	go func() {
		c := glpClient(p2pk)
		c.Start()
		for {
			select {
			case e := <-c.EventsChan:
				event := Event{}
				err := json.Unmarshal(e.Data, &event)
				sharedutils.CheckError(err)
				if event.Type == "public_endpoint" && event.Data["id"].(string) != myID {
					result <- event.Data["public_endpoint"].(string)
					return
				}
			}
		}
	}()

	return result
}

func buildP2PKey(key1, key2 string) string {
	if key2 < key1 {
		key1bak := key1
		key1 = key2
		key2 = key1bak
	}

	key1dec, err := base64.StdEncoding.DecodeString(key1)
	sharedutils.CheckError(err)
	key2dec, err := base64.StdEncoding.DecodeString(key2)
	sharedutils.CheckError(err)

	combined := append(key1dec, key2dec...)
	return base64.URLEncoding.EncodeToString(combined)
}

func getProfile(myID string) Profile {
	res, err := http.Get(server + "/profile/" + myID)
	sharedutils.CheckError(err)
	var p Profile
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&p)
	sharedutils.CheckError(err)
	return p
}

func getPeer(peerID string) Peer {
	res, err := http.Get(server + "/peer/" + peerID)
	sharedutils.CheckError(err)
	var p Peer
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&p)
	sharedutils.CheckError(err)
	return p
}
