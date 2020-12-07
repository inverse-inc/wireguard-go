package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"text/template"

	godnschange "github.com/inverse-inc/go-dnschange"
	"github.com/inverse-inc/wireguard-go/dns/coremain"
	"github.com/inverse-inc/wireguard-go/ztn"
)

func GenerateCoreDNSConfig(myDNSInfo *godnschange.DNSInfo, domains []string) string {

	var tpl bytes.Buffer

	type Data struct {
		Domains      []string
		Nameservers  string
		API          string
		SearchDomain []string
	}

	APIClient := ztn.GetAPIClient()

	data := Data{
		Domains:      domains,
		Nameservers:  strings.Join(myDNSInfo.NameServers[:], " "),
		API:          APIClient.Host,
		SearchDomain: myDNSInfo.SearchDomain,
	}

	t := template.New("Coreconfig")

	t, _ = t.Parse(
		`.:53 {
bind 127.0.0.69
#debug
{{ range .Domains }}
{{ if ne . "" }}
{{$domain := .}}
dnsredir {{.}} {
   to ietf-doh://{{ $.API }}:9999/dns-query
}
{{ range $.SearchDomain }}
{{ if ne . "" }}
dnsredir {{$domain}}.{{.}} {
	to ietf-doh://{{ $.API }}:9999/dns-query
}
{{ end }}
{{ end }}

{{ end }}
{{ end }}

forward . {{ .Nameservers }} {
	prefer_udp
}
}`)

	t.Execute(&tpl, data)
	return tpl.String()
}

func StartDNS() *godnschange.DNSStruct {
	dnsChange := godnschange.NewDNSChange()

	myDNSInfo := dnsChange.GetDNS()

	privateKey, publicKey := getKeys()

	profile := ztn.Profile{}
	profile.PrivateKey = base64.StdEncoding.EncodeToString(privateKey[:])
	profile.PublicKey = base64.StdEncoding.EncodeToString(publicKey[:])
	err := profile.FillProfileFromServer(connection, logger)
	if err != nil {
		logger.Error.Println("Got error when filling profile from server", err)
		connection.Update(func() {
			connection.Status = ztn.STATUS_ERROR
			connection.LastError = err
		})
		ztn.PauseOnError(quit)
	}

	buffer := GenerateCoreDNSConfig(myDNSInfo, profile.NamesToResolve)
	dnsChange.Change("127.0.0.69")
	go func() {
		coremain.Run(buffer)
	}()

	return dnsChange
}
