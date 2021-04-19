package main

//go:generate go run dns/directives_generate.go

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/wireguard-go/binutils"
	"github.com/inverse-inc/wireguard-go/device"
	_ "github.com/inverse-inc/wireguard-go/dns/core/plugin"
	"github.com/inverse-inc/wireguard-go/filter"
	"github.com/inverse-inc/wireguard-go/wgrpc"
	"github.com/inverse-inc/wireguard-go/ztn"
	ps "github.com/mitchellh/go-ps"

	_ "net/http/pprof"
)

const mainConnectionPort = 12673

var connection *ztn.Connection

var masterProcess bool

func setMasterProcess() {
	masterProcess = true
	setupMasterQuit()
}

func tryFindBindTechnique(todo func() bool) {
	done := false
	for !done {
		func() {
			for i := 1; i < 20; i++ {
				defer binutils.CapturePanic()
				done = todo()
				if done {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			done = true
		}()
	}
}

func startInverse(interfaceName string, device *device.Device) {
	defer binutils.CapturePanic()

	connection = ztn.NewConnection(logger)
	bindTechniqueDone := make(chan bool)

	go wgrpc.StartRPC(logger, connection, quit)

	go tryFindBindTechnique(func() bool {
		if ztn.NewUPNPIGD().CheckNet() == nil {
			logger.Info.Println("Router supports UPNP IGD, it will be used to create public P2P connections")
			ztn.BindTechniques.Add(ztn.BindUPNPIGD)
			go func() {
				bindTechniqueDone <- true
			}()
			return true
		} else {
			return false
		}
	})

	go tryFindBindTechnique(func() bool {
		if ztn.NewNATPMP().CheckNet() == nil {
			logger.Info.Println("Router supports NAT PMP, it will be used to create public P2P connections")
			ztn.BindTechniques.Add(ztn.BindNATPMP)
			go func() {
				bindTechniqueDone <- true
			}()
			return true
		} else {
			return false
		}
	})

	select {
	case <-bindTechniqueDone:
		logger.Info.Println("Was able to find a bind technique")
	case <-time.After(5 * time.Second):
		logger.Info.Println("Timeout trying to find a bind technique")
	}

	ztn.BindTechniques.Add(ztn.BindSTUN)
	ztn.BindTechniques.Add(ztn.BindThroughPeer)

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
		ztn.PauseOnError(quit)
	}

	connection.Profile = &profile

	detectNetworkChange(profile.STUNServer, func() {
		logger.Info.Println("Detected a network change, exiting...")
		quit()
	})

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
		ztn.PauseOnError(quit)
	}

	networkConnection := ztn.NewNetworkConnection("MAIN", logger, mainConnectionPort)
	networkConnection.Connection = connection

	wgrpc.WGRPCServer.SetNetworkConnection(networkConnection)
	wgrpc.WGRPCServer.AddDebugable(networkConnection)

	go networkConnection.Start()

	var enableRBACFilter uint32
	if profile.RBACIPFiltering {
		enableRBACFilter = 1
	}

	filter := filter.AclsToRulesFilter(profile.ACLs, filter.BuildRBACFilter(ztn.APIClientCtx, ztn.APIClient, &enableRBACFilter), nil)
	device.SetReceiveFilter(filter)

	for _, peerID := range profile.AllowedPeers {
		connection.StartPeer(device, profile, peerID, networkConnection)
	}

	go listenMyEvents(profile, connectNewPeerHandler(device, networkConnection, profile))

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

func connectNewPeerHandler(device *device.Device, networkConnection *ztn.NetworkConnection, profile ztn.Profile) func(ztn.Event) {
	pub, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	sharedutils.CheckError(err)
	myID := base64.URLEncoding.EncodeToString(pub[:])
	return func(event ztn.Event) {
		data := map[string]interface{}{}
		err = json.Unmarshal(event.Data, &data)
		if event.Type == "new_peer" && data["id"].(string) != myID {
			logger.Info.Println("Received new peer from pub/sub", data["id"].(string))
			connection.StartPeer(device, profile, data["id"].(string), networkConnection)
		}
	}
}

func listenMyEvents(profile ztn.Profile, eventHandler func(e ztn.Event)) {
	chal, err := ztn.GetServerChallenge(&profile)
	if err != nil {
		logger.Error.Println("Got an error while starting to listen events", err)
		if connection != nil {
			connection.Update(func() {
				connection.Status = ztn.STATUS_ERROR
				connection.LastError = err
			})
		}
	}

	priv, err := remoteclients.B64KeyToBytes(profile.PrivateKey)
	sharedutils.CheckError(err)
	pub, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	sharedutils.CheckError(err)
	serverPub, err := remoteclients.URLB64KeyToBytes(chal.PublicKey)
	sharedutils.CheckError(err)

	c := ztn.GLPPrivateClient(priv, pub, serverPub)
	c.LogErrors = true
	c.Start(ztn.APIClientCtx)
	for {
		select {
		case e := <-c.EventsChan:
			event := ztn.Event{}
			err := json.Unmarshal(e.Data, &event)
			sharedutils.CheckError(err)
			eventHandler(event)
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

func setupMasterQuit() {
	term := make(chan os.Signal, 1)
	go func() {
		signal.Notify(term, syscall.SIGTERM)
		signal.Notify(term, os.Interrupt)

		select {
		case <-term:
			quit()
		}
	}()

}

func quit() {
	fmt.Println("quit called in", os.Getpid())
	debug.PrintStack()
	if masterProcess {
		if DNSChange.Success {
			DNSChange.RestoreDNS("127.0.0.69")
		}
		fmt.Println("Master process is exiting")
	} else {
		ztn.UPNPIGDCleanupMapped()
	}
	os.Exit(0)
}
