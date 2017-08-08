// Package prifi-sda-service contains the SDA service responsible
// for starting the SDA protocols required to enable PriFi
// communications.
package services

/*
* This is the internal part of the API. As probably the prifi-service will
* not have an external API, this will not have any API-functions.
 */

import (
	"io/ioutil"
	"strconv"

	prifi_socks "github.com/lbarman/prifi/prifi-socks"
	prifi_protocol "github.com/lbarman/prifi/sda/protocols"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"time"
)

//The name of the service, used by SDA's internals
const ServiceName = "PriFiService"

var serviceID onet.ServiceID

// Register Service with SDA
func init() {
	onet.RegisterNewService(ServiceName, newService)
	serviceID = onet.ServiceFactory.ServiceID(ServiceName)
}

//Service contains the state of the service
type ServiceState struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	prifiTomlConfig           *prifi_protocol.PrifiTomlConfig
	Storage                   *Storage
	path                      string
	role                      prifi_protocol.PriFiRole
	relayIdentity             *network.ServerIdentity
	trusteeIDs                []*network.ServerIdentity
	connectToRelayStopChan    chan bool //spawned at init
	connectToRelay2StopChan   chan bool //spawned after receiving a HELLO message
	connectToTrusteesStopChan chan bool
	receivedHello             bool

	//If true, when the number of participants is reached, the protocol starts without calling StartPriFiCommunicateProtocol
	AutoStart bool

	//this hold the churn handler; protocol is started there. Only relay has this != nil
	churnHandler *churnHandler

	//this hold the running protocol (when it runs)
	PriFiSDAProtocol *prifi_protocol.PriFiSDAProtocol

	//used to hold "stoppers" for go-routines; send "true" to kill
	socksStopChan []chan bool

	hasSocksClientGoRoutine bool
	hasSocksServerGoRoutine bool
}

// Storage will be saved, on the contrary of the 'Service'-structure
// which has per-service information stored.
type Storage struct {
	//our service has no state to be saved
}

// newService receives the context and a path where it can write its
// configuration, if desired. As we don't know when the service will exit,
// we need to save the configuration on our own from time to time.
func newService(c *onet.Context) onet.Service {
	s := &ServiceState{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	helloMsg := network.RegisterMessage(HelloMsg{})
	stopSOCKSMsg := network.RegisterMessage(StopSOCKS{})
	stopMsg := network.RegisterMessage(StopProtocol{})
	connMsg := network.RegisterMessage(ConnectionRequest{})
	disconnectMsg := network.RegisterMessage(DisconnectionRequest{})

	c.RegisterProcessorFunc(helloMsg, s.HandleHelloMsg)
	c.RegisterProcessorFunc(stopMsg, s.HandleStop)
	c.RegisterProcessorFunc(stopSOCKSMsg, s.HandleStopSOCKS)
	c.RegisterProcessorFunc(connMsg, s.HandleConnection)
	c.RegisterProcessorFunc(disconnectMsg, s.HandleDisconnection)

	if err := s.tryLoad(); err != nil {
		log.Error(err)
	}

	return s
}

// NewProtocol is called on all nodes of a Tree (except the root, since it is
// the one starting the protocol) so it's the Service that will be called to
// generate the PI on all others node.
// If you use CreateProtocolSDA, this will not be called, as the SDA will
// instantiate the protocol on its own. If you need more control at the
// instantiation of the protocol, use CreateProtocolService, and you can
// give some extra-configuration to your protocol in here.
func (s *ServiceState) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {

	pi, err := prifi_protocol.NewPriFiSDAWrapperProtocol(tn)
	if err != nil {
		return nil, err
	}

	wrapper := pi.(*prifi_protocol.PriFiSDAProtocol)
	s.PriFiSDAProtocol = wrapper
	s.setConfigToPriFiProtocol(wrapper)

	return wrapper, nil
}

// Give the churnHandler the capacity to start the protocol by itself
func (s *ServiceState) RelayAllowAutoStart() {

	if s.churnHandler == nil {
		log.Fatal("Cannot allow auto start when relay has not been initialized")
	}
	s.churnHandler.startProtocol = s.StartPriFiCommunicateProtocol
}

// StartRelay starts the necessary
// protocols to enable the relay-mode.
// In this example it simply starts the demo protocol
func (s *ServiceState) StartRelay(group *app.Group) error {
	log.Info("Service", s, "running in relay mode")

	//set state to the correct info, parse .toml
	s.role = prifi_protocol.Relay
	relayID, trusteesIDs := mapIdentities(group)
	s.relayIdentity = relayID //should not be used in the case of the relay

	//creates the ChurnHandler, part of the Relay's Service, that will start/stop the protocol
	s.churnHandler = new(churnHandler)
	s.churnHandler.init(relayID, trusteesIDs)
	s.churnHandler.isProtocolRunning = s.IsPriFiProtocolRunning
	if s.AutoStart {
		s.churnHandler.startProtocol = s.StartPriFiCommunicateProtocol
	} else {
		s.churnHandler.startProtocol = nil
	}
	s.churnHandler.stopProtocol = s.StopPriFiCommunicateProtocol

	socksServerConfig = &prifi_protocol.SOCKSConfig{
		Port:              "127.0.0.1:" + strconv.Itoa(s.prifiTomlConfig.SocksClientPort),
		PayloadLength:     s.prifiTomlConfig.CellSizeUp,
		UpstreamChannel:   make(chan []byte),
		DownstreamChannel: make(chan []byte),
	}

	//the relay has a socks Client
	if !s.hasSocksClientGoRoutine {
		stopChan := make(chan bool, 1)
		go prifi_socks.StartSocksClient(socksServerConfig.Port, socksServerConfig.UpstreamChannel, socksServerConfig.DownstreamChannel, stopChan)
		s.socksStopChan = append(s.socksStopChan, stopChan)
		s.hasSocksClientGoRoutine = true
	}

	s.connectToTrusteesStopChan = make(chan bool)
	go s.connectToTrustees(trusteesIDs, s.connectToTrusteesStopChan)

	return nil
}

// StartClient starts the necessary
// protocols to enable the client-mode.
func (s *ServiceState) StartClient(group *app.Group, delay time.Duration) error {
	log.Info("Service", s, "running in client mode")
	s.role = prifi_protocol.Client

	relayID, trusteeIDs := mapIdentities(group)
	s.relayIdentity = relayID

	socksClientConfig = &prifi_protocol.SOCKSConfig{
		Port:              ":" + strconv.Itoa(s.prifiTomlConfig.SocksServerPort),
		PayloadLength:     s.prifiTomlConfig.CellSizeUp,
		UpstreamChannel:   make(chan []byte),
		DownstreamChannel: make(chan []byte),
	}

	//the client has a socks server
	if !s.hasSocksServerGoRoutine {
		log.Lvl1("Starting SOCKS server on port", socksClientConfig.Port)
		stopChan := make(chan bool, 1)
		go prifi_socks.StartSocksServer(socksClientConfig.Port, socksClientConfig.PayloadLength, socksClientConfig.UpstreamChannel, socksClientConfig.DownstreamChannel, s.prifiTomlConfig.DoLatencyTests, stopChan)
		s.socksStopChan = append(s.socksStopChan, stopChan)
		s.hasSocksServerGoRoutine = true
	}

	s.connectToRelayStopChan = make(chan bool)
	s.trusteeIDs = trusteeIDs

	go func() {
		if delay > 0 {
			log.Lvl1("Client sleeping for", (delay * time.Second))
			time.Sleep(delay * time.Second)
			log.Lvl1("Client done sleeping (for", (delay * time.Second), ")")
		}
		go s.connectToRelay(relayID, s.connectToRelayStopChan)
	}()

	return nil
}

// StartClient starts the necessary
// protocols to enable the client-mode.
func (s *ServiceState) StartSocksTunnelOnly() error {
	log.Info("Service", s, "running in socks-tunnel-only mode")

	socksClientConfig = &prifi_protocol.SOCKSConfig{
		Port:              ":" + strconv.Itoa(s.prifiTomlConfig.SocksServerPort),
		PayloadLength:     s.prifiTomlConfig.CellSizeUp,
		UpstreamChannel:   make(chan []byte),
		DownstreamChannel: make(chan []byte),
	}

	socksServerConfig = &prifi_protocol.SOCKSConfig{
		Port:              "127.0.0.1:" + strconv.Itoa(s.prifiTomlConfig.SocksClientPort),
		PayloadLength:     s.prifiTomlConfig.CellSizeUp,
		UpstreamChannel:   socksClientConfig.UpstreamChannel,
		DownstreamChannel: socksClientConfig.DownstreamChannel,
	}
	stopChan1 := make(chan bool, 1)
	stopChan2 := make(chan bool, 1)
	go prifi_socks.StartSocksServer(socksClientConfig.Port, socksClientConfig.PayloadLength, socksClientConfig.UpstreamChannel, socksClientConfig.DownstreamChannel, false, stopChan1)
	go prifi_socks.StartSocksClient(socksServerConfig.Port, socksServerConfig.UpstreamChannel, socksServerConfig.DownstreamChannel, stopChan2)
	s.socksStopChan = append(s.socksStopChan, stopChan1)
	s.socksStopChan = append(s.socksStopChan, stopChan2)

	return nil
}

// StartTrustee starts the necessary
// protocols to enable the trustee-mode.
func (s *ServiceState) StartTrustee(group *app.Group) error {
	log.Info("Service", s, "running in trustee mode")
	s.role = prifi_protocol.Trustee

	//the this might fail if the relay is behind a firewall. The HelloMsg is to fix this
	relayID, _ := mapIdentities(group)
	s.relayIdentity = relayID

	s.connectToRelayStopChan = make(chan bool)
	go s.connectToRelay(relayID, s.connectToRelayStopChan)

	return nil
}

// CleanResources kill all goroutines related to SOCKS on this service
func (s *ServiceState) ShutdownSocks() error {
	log.Lvl2("Stopping service's SOCKS goroutines.")

	for _, v := range s.socksStopChan {
		v <- true
	}

	return nil
}

// CleanResources kill all goroutines on all services
func (s *ServiceState) GlobalShutDownSocks() error {
	log.Lvl2("Stopping globally all SOCKS goroutines.")

	//contact the clients
	for _, v := range s.churnHandler.getClientsIdentities() {
		s.SendRaw(v, &StopSOCKS{})
	}

	//shut down the relay's SOCKS
	s.ShutdownSocks()

	return nil
}

// save saves the actual identity
func (s *ServiceState) save() {
	log.Lvl3("Saving service")
	b, err := network.Marshal(s.Storage)
	if err != nil {
		log.Error("Couldn't marshal service:", err)
	} else {
		err = ioutil.WriteFile(s.path+"/prifi.bin", b, 0660)
		if err != nil {
			log.Error("Couldn't save file:", err)
		}
	}
}
