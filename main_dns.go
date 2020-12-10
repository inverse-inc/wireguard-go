package main

import (
	"bytes"
	"encoding/base64"
	"net"
	"strings"
	"text/template"
	"time"

	godnschange "github.com/inverse-inc/go-dnschange"
	"github.com/inverse-inc/wireguard-go/dns/coremain"
	"github.com/inverse-inc/wireguard-go/ztn"
)

var CoreDNSConfig *string

func GenerateCoreDNSConfig(myDNSInfo *godnschange.DNSInfo, profile ztn.Profile) string {

	var tpl bytes.Buffer

	type Data struct {
		Domains      []string
		Nameservers  string
		ZTNPeers     []string
		API          string
		SearchDomain []string
		ZTNServer    bool
	}

	APIClient := ztn.GetAPIClient()

	ZTNAddr := false

	if net.ParseIP(APIClient.Host) == nil {
		_, err := net.LookupIP(APIClient.Host)
		if err != nil {
			logger.Error.Println("Unknown host ", APIClient.Host)
		} else {
			ZTNAddr = true
		}
	}

	data := Data{
		Domains:      profile.DomainsToResolve,
		ZTNPeers:     profile.NamesToResolve,
		Nameservers:  strings.Join(myDNSInfo.NameServers[:], " "),
		API:          APIClient.Host,
		SearchDomain: myDNSInfo.SearchDomain,
		ZTNServer:    ZTNAddr,
	}

	t := template.New("Coreconfig")

	t, _ = t.Parse(
		`.:53 {
bind 127.0.0.69
reload
#debug
{{ range .Domains }}
{{ if ne . "" }}
{{$domain := .}}
dnsredir {{.}} {
   to ietf-doh://{{ $.API }}:9999/dns-query
}
{{ end }}
{{ end }}

{{ range .ZTNPeers }}
{{ if ne . "" }}
{{$ztnpeer := .}}

dnsredir {{.}} {
	to ietf-doh://{{ $.API }}:9999/dns-ztn-query
}

{{ range $.SearchDomain }}
{{ if ne . "" }}

dnsredir {{$ztnpeer}}.{{.}} {
	to ietf-doh://{{ $.API }}:9999/dns-ztn-query
}

{{ end }}
{{ end }}

{{ end }}
{{ end }}

{{ if .ZTNServer }}
forward {{ .API }} {{ .Nameservers }} {
	prefer_udp
}
{{ end }}

forward . {{ .Nameservers }} {
	prefer_udp
}
}`)

	t.Execute(&tpl, data)
	logger.Debug.Println(tpl.String())
	return tpl.String()
}

func StartDNS() *godnschange.DNSStruct {
	CoreDNSConfig = nil

	dnsChange := godnschange.NewDNSChange()

	myDNSInfo := dnsChange.GetDNS()

	privateKey, publicKey := getKeys()

	profile := ztn.Profile{}
	profile.PrivateKey = base64.StdEncoding.EncodeToString(privateKey[:])
	profile.PublicKey = base64.StdEncoding.EncodeToString(publicKey[:])

	err := profile.FillProfileFromServer(connection, logger)
	if err != nil {
		logger.Error.Println("Got error when filling profile from server", err)
		dnsChange.Success = false
	} else {
		conf := GenerateCoreDNSConfig(myDNSInfo, profile)
		CoreDNSConfig = &conf
		err := dnsChange.Change("127.0.0.69")
		if err != nil {
			dnsChange.Success = false
		} else {
			dnsChange.Success = true
			go func() {
				coremain.Run(*CoreDNSConfig)
			}()
			go func() {
				for {
					time.Sleep(10 * time.Second)
					err := profile.FillProfileFromServer(connection, logger)
					if err != nil {
						logger.Error.Println("Something went wrong on profile refresh", err)
						dnsChange.Success = false
					}
					conf = GenerateCoreDNSConfig(myDNSInfo, profile)
					CoreDNSConfig = &conf
				}
			}()
		}
	}

	return dnsChange
}
