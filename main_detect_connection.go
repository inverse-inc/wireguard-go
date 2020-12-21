package main

import (
	"fmt"
	"net"
	"time"
)

func detectNetworkChange(serverHost string, onchange func()) {
	go func() {
		zeroIP := net.IPv4(0, 0, 0, 0)
		lastFail := time.Time{}
		lastSuccess := time.Time{}
		lastIP := zeroIP
		failTolerance := 60 * time.Second
		sleepDetectTolerance := failTolerance

		for {
			conn, err := net.Dial("udp", serverHost)
			if err != nil {
				lastSuccess = time.Time{}

				if lastFail.IsZero() {
					lastFail = time.Now()
				} else if time.Since(lastFail) > failTolerance {
					// Reset the last fail so that if it keeps failing it will only trigger again once failTolerance has elapsed
					lastFail = time.Time{}
					fmt.Println("Too many network failure, triggering network change event")
					go onchange()
				}
			} else {
				conn.Close()
				lastFail = time.Time{}
				newIP := conn.LocalAddr().(*net.UDPAddr).IP

				if lastSuccess.IsZero() {
					lastSuccess = time.Now()
				} else if time.Since(lastSuccess) >= sleepDetectTolerance {
					// Reset the last success so that it will only trigger again once sleepDetectTolerance has elapsed again
					lastSuccess = time.Time{}
					fmt.Println("Last successful connection dates from too long, triggering network change event")
					go onchange()
				} else {
					lastSuccess = time.Now()
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
