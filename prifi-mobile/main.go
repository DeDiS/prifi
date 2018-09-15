/*
 * The package name must NOT contain underscore.
 */
package prifiMobile

import (
	prifi_service "github.com/dedis/prifi/sda/services"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"time"
	"gopkg.in/dedis/onet.v2/network"
)

var stopChan chan bool
var errorChan chan error
var globalHost *onet.Server
var globalService *prifi_service.ServiceState

// The "main" function that is called by Mobile OS in order to launch a client server
func StartClient() error {
	stopChan = make(chan bool, 1)
	errorChan = make(chan error, 1)

	go func() {
		errorChan <- run()
	}()

	select {
	case err := <-errorChan:
		log.Error("Error occurs", err)
		return err
	case <-stopChan:

		// Stop goroutines
		globalService.ShutdownConnexionToRelay()
		globalService.ShutdownSocks()

		// Change the protocol state to SHUTDOWN
		globalService.StopPriFiCommunicateProtocol()

		// Clean network-related resources
		globalHost.Close()

		log.Info("PriFi Session Ended")
		return nil
	}
}

func StopClient() {
	stopChan <- true
}

func run() error {
	host, group, service, err := startCothorityNode()
	globalHost = host
	globalService = service

	if err != nil {
		log.Error("Could not start the cothority node:", err)
		return err
	}

	if err := service.StartClient(group, time.Duration(0)); err != nil {
		log.Error("Could not start the PriFi service:", err)
		return err
	}

	host.Router.AddErrorHandler(networkErrorHappenedForMobile)
	host.Start()

	// Never return
	return nil
}

func networkErrorHappenedForMobile(si *network.ServerIdentity) {
	log.Lvl3("Mobile Client: A network error occurred with node", si)
	globalService.StopPriFiCommunicateProtocol()

	doWeDisconnectWhenNetworkError, err := GetMobileDisconnectWhenNetworkError()
	if err != nil {
		log.Error("Error occurs while reading MobileDisconnectWhenNetworkError.")
	}

	if doWeDisconnectWhenNetworkError {
		StopClient()
	} else {
		go timeout()
	}
}

func timeout() {
	select {
	case <-time.After(30 * time.Second):
		if !globalService.IsPriFiProtocolRunning() {
			log.Lvl2("Timeout triggered")
			StopClient()
		} else {
			log.Lvl2("Timeout not triggered")
		}
	}
}