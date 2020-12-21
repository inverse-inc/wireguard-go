package main

import (
	"fmt"
	"net"
	"time"
)

func detectNetworkChange(serverHost string, onchange func()) {
	go func() {
		zeroIP := net.IPv4(0, 0, 0, 0)
		var lastFail int64 = 0
		var lastSuccess int64 = 0
		lastIP := zeroIP
		var failTolerance int64 = 60
		sleepDetectTolerance := failTolerance

		for {
			time.Sleep(1 * time.Second)
			conn, err := net.Dial("udp", serverHost)
			if err != nil {
				lastSuccess = 0

				if lastFail == 0 {
					lastFail = time.Now().Unix()
				} else if time.Now().Unix()-lastFail >= failTolerance {
					// Reset the last fail so that if it keeps failing it will only trigger again once failTolerance has elapsed
					lastFail = 0
					fmt.Println("Too many network failure, triggering network change event")
					go onchange()
				}
			} else {
				conn.Close()
				lastFail = 0
				newIP := conn.LocalAddr().(*net.UDPAddr).IP

				if lastSuccess == 0 {
					lastSuccess = time.Now().Unix()
				} else if time.Now().Unix()-lastSuccess >= sleepDetectTolerance {
					// Reset the last success so that it will only trigger again once sleepDetectTolerance has elapsed again
					lastSuccess = 0
					fmt.Println("Last successful connection dates from too long, triggering network change event")
					go onchange()
				} else {
					lastSuccess = time.Now().Unix()
				}

				if lastIP.IsUnspecified() {
					lastIP = newIP
				} else if !lastIP.Equal(newIP) {
					lastIP = newIP
					fmt.Println("IP address has changed, triggering network change event")
					go onchange()
				}
			}
		}
	}()
}
