package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"runtime/debug"

	"github.com/davecgh/go-spew/spew"
	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn"
)

func startInverse(interfaceName string, device *device.Device) {
	privateKey, publicKey := getKeys()

	profile := ztn.Profile{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey[:]),
	}
	profile.FillProfileFromServer(logger)

	profile.SetupWireguard(device, interfaceName)

	for _, peerID := range profile.AllowedPeers {
		startPeer(device, profile, peerID)
	}

	go listenEvents(device, profile)

	go func() {
		//PPROF
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}

func getKeys() ([32]byte, [32]byte) {
	usr, err := user.Current()
	sharedutils.CheckError(err)
	authFile := path.Join(usr.HomeDir, "auth.json")

	logger.Info.Println("Using auth file:", authFile)

	auth := struct {
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
	}{}

	if _, statErr := os.Stat(authFile); statErr == nil {
		f, err := os.Open(authFile)
		if err != nil {
			panic("Unable to open " + authFile + ": " + err.Error())
		}
		defer f.Close()

		err = json.NewDecoder(f).Decode(&auth)
		sharedutils.CheckError(err)
		priv, err := remoteclients.B64KeyToBytes(auth.PrivateKey)
		sharedutils.CheckError(err)
		pub, err := remoteclients.B64KeyToBytes(auth.PublicKey)
		sharedutils.CheckError(err)
		return priv, pub
	} else {
		f, err := os.Create(authFile)
		if err != nil {
			panic("Unable to create " + authFile + ": " + err.Error())
		}
		defer f.Close()

		priv, err := remoteclients.GeneratePrivateKey()
		sharedutils.CheckError(err)
		pub, err := remoteclients.GeneratePublicKey(priv)
		sharedutils.CheckError(err)
		auth.PrivateKey = base64.StdEncoding.EncodeToString(priv[:])
		auth.PublicKey = base64.StdEncoding.EncodeToString(pub[:])
		spew.Dump(auth)
		err = json.NewEncoder(f).Encode(&auth)
		sharedutils.CheckError(err)
		return priv, pub
	}
}

func listenEvents(device *device.Device, profile ztn.Profile) {
	chal, err := ztn.GetServerChallenge(&profile)
	sharedutils.CheckError(err)
	priv, err := remoteclients.B64KeyToBytes(profile.PrivateKey)
	sharedutils.CheckError(err)
	pub, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	sharedutils.CheckError(err)
	serverPub, err := remoteclients.URLB64KeyToBytes(chal.PublicKey)
	sharedutils.CheckError(err)

	myID := base64.URLEncoding.EncodeToString(pub[:])
	c := ztn.GLPPrivateClient(priv, pub, serverPub)
	c.Start(ztn.APIClientCtx)
	for {
		select {
		case e := <-c.EventsChan:
			event := ztn.Event{}
			err := json.Unmarshal(e.Data, &event)
			sharedutils.CheckError(err)
			if event.Type == "new_peer" && event.Data["id"].(string) != myID {
				startPeer(device, profile, event.Data["id"].(string))
			}
		}
	}
}

func startPeer(device *device.Device, profile ztn.Profile, peerID string) {
	peerProfile, err := ztn.GetPeerProfile(peerID)
	if err != nil {
		logger.Error.Println("Unable to fetch profile for peer", peerID, ". Error:", err)
		logger.Error.Println(debug.Stack())
	} else {
		go func(peerID string, peerProfile ztn.PeerProfile) {
			for {
				func() {
					defer func() {
						if r := recover(); r != nil {
							logger.Error.Println("Recovered error", r, "while handling peer", peerProfile.PublicKey, ". Will attempt to connect to it again.")
						}
					}()
					pc := ztn.NewPeerConnection(device, logger, profile, peerProfile)
					pc.Start()
				}()
			}
		}(peerID, peerProfile)
	}
}
