package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"time"

	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/binutils"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/filter"
	"github.com/inverse-inc/wireguard-go/util"
	"github.com/inverse-inc/wireguard-go/wgrpc"
	"github.com/inverse-inc/wireguard-go/ztn"
	ps "github.com/mitchellh/go-ps"

	_ "net/http/pprof"
)

const mainConnectionPort = 12673

var connection *ztn.Connection

func startInverse(interfaceName string, device *device.Device) {
	defer binutils.CapturePanic()

	connection = ztn.NewConnection(logger)
	bindTechniqueDone := make(chan bool)

	go func() {
		defer binutils.CapturePanic()

		if ztn.NewUPNPIGD().CheckNet() == nil {
			logger.Debug.Println("Router supports UPNP IGD, it will be used to create public P2P connections")
			ztn.BindTechniques.Add(ztn.BindUPNPIGD)
			bindTechniqueDone <- true
		}
	}()

	go func() {
		defer binutils.CapturePanic()

		if ztn.NewNATPMP().CheckNet() == nil {
			logger.Debug.Println("Router supports NAT PMP, it will be used to create public P2P connections")
			ztn.BindTechniques.Add(ztn.BindNATPMP)
			bindTechniqueDone <- true
		}
	}()

	select {
	case <-bindTechniqueDone:
		logger.Info.Println("Was able to find a bind technique")
	case <-time.After(5 * time.Second):
		logger.Info.Println("Timeout trying to find a bind technique")
	}

	ztn.BindTechniques.Add(ztn.BindSTUN)

	if !ztn.RunningInCLI() {
		go checkParentIsAlive()
	}

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
		util.Pause()
	}

	connection.Update(func() {
		connection.Status = ztn.STATUS_FETCHING_PEERS
		connection.LastError = err
	})

	err = profile.SetupWireguard(device, interfaceName)
	if err != nil {
		logger.Error.Println("Got error when setting up wireguard interface", err)
		connection.Update(func() {
			connection.Status = ztn.STATUS_ERROR
			connection.LastError = err
		})
		util.Pause()
	}

	networkConnection := ztn.NewNetworkConnection("MAIN", logger, mainConnectionPort)
	networkConnection.Connection = connection

	go wgrpc.StartRPC(logger, connection, networkConnection, quit)

	go networkConnection.Start()

	filter := filter.NewFilterFromAcls(profile.ACLs)
	device.SetReceiveFilter(filter)

	for _, peerID := range profile.AllowedPeers {
		connection.StartPeer(device, profile, peerID, networkConnection)
	}

	go listenEvents(device, profile, networkConnection)

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

	return remoteclients.GetKeysFromFile(authFile)
}

func listenEvents(device *device.Device, profile ztn.Profile, networkConnection *ztn.NetworkConnection) {
	chal, err := ztn.GetServerChallenge(&profile)
	if err != nil {
		logger.Error.Println("Got an error while starting to listen events", err)
		connection.Update(func() {
			connection.Status = ztn.STATUS_ERROR
			connection.LastError = err
		})
	}

	priv, err := remoteclients.B64KeyToBytes(profile.PrivateKey)
	sharedutils.CheckError(err)
	pub, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	sharedutils.CheckError(err)
	serverPub, err := remoteclients.URLB64KeyToBytes(chal.PublicKey)
	sharedutils.CheckError(err)

	myID := base64.URLEncoding.EncodeToString(pub[:])
	c := ztn.GLPPrivateClient(priv, pub, serverPub)
	c.LogErrors = true
	c.Start(ztn.APIClientCtx)
	for {
		select {
		case e := <-c.EventsChan:
			event := ztn.Event{}
			err := json.Unmarshal(e.Data, &event)
			sharedutils.CheckError(err)
			data := map[string]interface{}{}
			err = json.Unmarshal(event.Data, &data)
			if event.Type == "new_peer" && data["id"].(string) != myID {
				logger.Info.Println("Received new peer from pub/sub", data["id"].(string))
				connection.StartPeer(device, profile, data["id"].(string), networkConnection)
			}
		}
	}
}

func findppid(pid int) int {
	list, err := ps.Processes()
	if err != nil {
		sharedutils.CheckError(err)
	}
	for _, p := range list {
		if p.Pid() == pid {
			return p.PPid()
		}
	}
	return 0
}

func quit() {
	ztn.UPNPIGDCleanupMapped()
	os.Exit(0)
}
