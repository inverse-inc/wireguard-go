package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"strings"
	"text/template"
	"time"

	godnschange "github.com/inverse-inc/go-dnschange"
	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/timedlock"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/dns/coremain"
	"github.com/inverse-inc/wireguard-go/ztn"
)

// LocalDNS is the ip address CoreDNS will listen
const LocalDNS = "127.0.0.69"

// CoreDNSConfig contain the dns configuration
var CoreDNSConfig *string

// GlobalTransactionLock global var
var GlobalTransactionLock *timedlock.RWLock

var newPeer = make(chan string)

func GenerateCoreDNSConfig(myDNSInfo *godnschange.DNSInfo, profile ztn.Profile, APIClient *unifiedapiclient.Client) string {

	id, _ := GlobalTransactionLock.RLock()

	defer GlobalTransactionLock.RUnlock(id)

	var tpl bytes.Buffer

	type Data struct {
		Domains        []string
		Nameservers    string
		ZTNPeers       []string
		API            string
		SearchDomain   []string
		InternalDomain string
		ZTNServer      bool
		Port           string
	}

	ZTNAddr := false

	if net.ParseIP(APIClient.Host) == nil {
		_, err := net.LookupIP(APIClient.Host)
		if err != nil {
			logger.Error.Println("Unknown host ", APIClient.Host)
		} else {
			ZTNAddr = true
		}
	}

	// Add local machine
	hostname, err := os.Hostname()
	var Peers []string
	if err != nil {
		Peers = profile.NamesToResolve
	} else {
		Peers = append(profile.NamesToResolve, hostname)
	}
	data := Data{
		Domains:        profile.DomainsToResolve,
		ZTNPeers:       Peers,
		Nameservers:    strings.Join(myDNSInfo.NameServers[:], " "),
		API:            APIClient.Host,
		SearchDomain:   myDNSInfo.SearchDomain,
		ZTNServer:      ZTNAddr,
		InternalDomain: profile.InternalDomainToResolve,
		Port:           APIClient.Port,
	}

	t := template.New("Coreconfig")

	t, _ = t.Parse(
		`.:53 {
bind 127.0.0.69
reload
#debug
{{ range .Domains }}{{ if ne . "" }}{{$domain := .}}
dnsredir {{.}} {
   to ietf-doh://{{ $.API }}:{{$.Port}}/dns-query
}
{{ end }}{{ end }}
dnsredir {{$.InternalDomain}} {
	to ietf-doh://{{ $.API }}:{{$.Port}}/dns-ztn-query
}

{{ range .ZTNPeers }}{{ if ne . "" }}{{$ztnpeer := .}}
{{ range $.SearchDomain }}{{ if ne . "" }}
dnsredir {{$ztnpeer}}.{{.}} {
	to ietf-doh://{{ $.API }}:{{$.Port}}/dns-ztn-query
}
{{ end }}{{ end }}{{ end }}{{ end }}
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
	GlobalTransactionLock = timedlock.NewRWLock()
	GlobalTransactionLock.Panic = false
	GlobalTransactionLock.PrintErrors = true
	dnsChange := godnschange.NewDNSChange()

	myDNSInfo := dnsChange.GetDNS()

	if !sharedutils.IsEnabled(sharedutils.EnvOrDefault(ztn.EnvSetupDNS, "true")) {
		logger.Info.Println("Not setting up DNS due to environment variable " + ztn.EnvSetupDNS)
		return dnsChange
	}

	privateKey, publicKey := getKeys()

	APIClient := ztn.GetAPIClient()

	profile := ztn.Profile{}
	profile.PrivateKey = base64.StdEncoding.EncodeToString(privateKey[:])
	profile.PublicKey = base64.StdEncoding.EncodeToString(publicKey[:])

	err := profile.FillProfileFromServer(connection, logger)
	if err != nil {
		logger.Error.Println("Got error when filling profile from server", err)
		dnsChange.Success = false
	} else {
		detectNetworkChange(profile.STUNServer, func() {
			// Recover dns configuration
			dnsChange.RestoreDNS(LocalDNS)
			dnsChange := godnschange.NewDNSChange()
			myDNSInfo := dnsChange.GetDNS()
			conf := GenerateCoreDNSConfig(myDNSInfo, profile, APIClient)
			CoreDNSConfig = &conf
			err := dnsChange.Change(LocalDNS, profile.DomainsToResolve, profile.NamesToResolve, profile.InternalDomainToResolve, APIClient.Host)
			if err != nil {
				dnsChange.Success = false
			} else {
				dnsChange.Success = true
			}
		})

		go listenMyEvents(profile, dnsNewPeerHandler(profile))

		conf := GenerateCoreDNSConfig(myDNSInfo, profile, APIClient)
		CoreDNSConfig = &conf
		// Clean old modifications
		dnsChange.RestoreDNS(LocalDNS)
		err := dnsChange.Change(LocalDNS, profile.DomainsToResolve, profile.NamesToResolve, profile.InternalDomainToResolve, APIClient.Host)
		if err != nil {
			dnsChange.Success = false
		} else {
			dnsChange.Success = true
			go func(CoreDNSConfig *string) {
				defer recoverDns(CoreDNSConfig)
				coremain.Run(CoreDNSConfig)
			}(CoreDNSConfig)
			go func() {
				pooling(connection, logger, myDNSInfo, &profile, dnsChange, &conf, APIClient)
			}()
		}
	}

	return dnsChange
}

func recoverDns(CoreDNSConfig *string) {
	if r := recover(); r != nil {
		go func(CoreDNSConfig *string) {
			defer recoverDns(CoreDNSConfig)
			coremain.Run(CoreDNSConfig)
		}(CoreDNSConfig)
	}
}

func pooling(connection *ztn.Connection, logger *device.Logger, myDNSInfo *godnschange.DNSInfo, profile *ztn.Profile, dnsChange *godnschange.DNSStruct, conf *string, APIClient *unifiedapiclient.Client) {
	for {
		select {
		case <-newPeer:
			logger.Info.Println("Discovered new peer, reload DNS configuration")
			defer recoverPooling(connection, logger, myDNSInfo, profile, dnsChange, conf, APIClient)
			err := profile.FillProfileFromServer(connection, logger)
			if err != nil {
				logger.Error.Println("Something went wrong on profile refresh", err)
			}
			*conf = GenerateCoreDNSConfig(myDNSInfo, *profile, APIClient)
			if *conf != *CoreDNSConfig {
				CoreDNSConfig = conf
				dnsChange.RestoreDNS(LocalDNS)
				err := dnsChange.Change(LocalDNS, profile.DomainsToResolve, profile.NamesToResolve, profile.InternalDomainToResolve, APIClient.Host)
				if err != nil {
					logger.Error.Println("Unable to change the dns configuration ", err)
				}
			}
		case <-time.After(10 * time.Minute):
			defer recoverPooling(connection, logger, myDNSInfo, profile, dnsChange, conf, APIClient)
			err := profile.FillProfileFromServer(connection, logger)
			if err != nil {
				logger.Error.Println("Something went wrong on profile refresh", err)
			}
			*conf = GenerateCoreDNSConfig(myDNSInfo, *profile, APIClient)
			if *conf != *CoreDNSConfig {
				CoreDNSConfig = conf
				dnsChange.RestoreDNS(LocalDNS)
				err := dnsChange.Change(LocalDNS, profile.DomainsToResolve, profile.NamesToResolve, profile.InternalDomainToResolve, APIClient.Host)
				if err != nil {
					logger.Error.Println("Unable to change the dns configuration ", err)
				}
			}
		}
	}
}

func recoverPooling(connection *ztn.Connection, logger *device.Logger, myDNSInfo *godnschange.DNSInfo, profile *ztn.Profile, dnsChange *godnschange.DNSStruct, conf *string, APIClient *unifiedapiclient.Client) {
	if r := recover(); r != nil {
		go func() {
			pooling(connection, logger, myDNSInfo, profile, dnsChange, conf, APIClient)
		}()
	}
}

func dnsNewPeerHandler(profile ztn.Profile) func(ztn.Event) {
	pub, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	sharedutils.CheckError(err)
	myID := base64.URLEncoding.EncodeToString(pub[:])
	return func(event ztn.Event) {
		data := map[string]interface{}{}
		err = json.Unmarshal(event.Data, &data)
		if event.Type == "new_peer" && data["id"].(string) != myID {
			logger.Info.Println("Received new peer from pub/sub", data["id"].(string))
			go func() {
				newPeer <- data["id"].(string)
			}()
		}
	}
}
