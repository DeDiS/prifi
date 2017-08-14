package services

import (
	prifi_protocol "github.com/lbarman/prifi/sda/protocols"
	"github.com/lbarman/prifi/utils"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"time"
)

// Packet send by relay when some node disconnected
type StopProtocol struct{}

// Packet send by relay doing simulations to stop the SOCKS stuff
type StopSOCKS struct{}

// ConnectionRequest messages are sent to the relay
// by nodes that want to join the protocol.
type ConnectionRequest struct {
	ProtocolVersion string
}

// HelloMsg messages are sent by the relay to the trustee;
// if they are up, they answer with a ConnectionRequest
type HelloMsg struct{}

// DisconnectionRequest messages are sent to the relay
// by nodes that want to leave the protocol.
type DisconnectionRequest struct{}

//Delay before each host re-tried to connect to the relay
const DELAY_BEFORE_CONNECT_TO_RELAY = 5 * time.Second

//Delay before the relay re-tried to connect to the trustees
const DELAY_BEFORE_CONNECT_TO_TRUSTEES = 30 * time.Second

// returns true if the PriFi SDA protocol is running (in any state : init, communicate, etc)
func (s *ServiceState) IsPriFiProtocolRunning() bool {
	if s.PriFiSDAProtocol != nil {
		return !s.PriFiSDAProtocol.HasStopped
	}
	return false
}

// Packet send by relay; when we get it, we stop the protocol
func (s *ServiceState) HandleStop(msg *network.Envelope) {
	log.Lvl1("Received a Handle Stop (I'm ", s.role, ")")
	s.StopPriFiCommunicateProtocol()
}

// Packet send by relay to trustees at start
func (s *ServiceState) HandleHelloMsg(msg *network.Envelope) {
	if s.role != prifi_protocol.Trustee {
		log.Error("Received a Hello message, but we're not a trustee ! ignoring.")
		return
	}

	if !s.receivedHello {
		//start sending some ConnectionRequests
		s.relayIdentity = msg.ServerIdentity
		s.connectToRelay2StopChan = make(chan bool, 1)
		go s.connectToRelay(s.relayIdentity, s.connectToRelay2StopChan)
		s.receivedHello = true
	}

}

// Packet received by relay when some node connects
func (s *ServiceState) HandleConnection(msg *network.Envelope) {
	if s.churnHandler == nil {
		log.Fatal("Can't handle a connection without a churnHandler")
	}

	if s.prifiTomlConfig.ProtocolVersion != msg.Msg.(*ConnectionRequest).ProtocolVersion {
		log.Fatal("Different CommitID between relay and ", msg.ServerIdentity.String())
	}

	s.churnHandler.handleConnection(msg)
}

// Packet send by relay when some node disconnected
func (s *ServiceState) HandleDisconnection(msg *network.Envelope) {
	if s.churnHandler == nil {
		log.Fatal("Can't handle a disconnection without a churnHandler")
	}
	s.churnHandler.handleDisconnection(msg)
}

// Packet send by relay when some node disconnected
func (s *ServiceState) HandleStopSOCKS(msg *network.Envelope) {
	s.ShutdownSocks()
}

// handleTimeout is a callback that should be called on the relay
// when a round times out. It tries to restart PriFi with the nodes
// that sent their ciphertext in time.
func (s *ServiceState) handleTimeout(lateClients []string, lateTrustees []string) {

	// we can probably do something more clever here, since we know who disconnected. Yet let's just restart everything
	s.NetworkErrorHappened(nil)
}

// This is a handler passed to the SDA when starting a host. The SDA usually handle all the network by itself,
// but in our case it is useful to know when a network RESET occurred, so we can kill protocols (otherwise they
// remain in some weird state)
func (s *ServiceState) NetworkErrorHappened(si *network.ServerIdentity) {

	if s.role != prifi_protocol.Relay {
		log.Lvl3("A network error occurred with node", si, ", but we're not the relay, nothing to do.")
		s.connectToRelayStopChan <- true //"nothing" except stop this goroutine
		return
	}
	if s.churnHandler == nil {
		log.Fatal("Can't handle a network error without a churnHandler")
	}

	log.Error("A network error occurred with node", si, ", warning other clients.")
	s.churnHandler.handleUnknownDisconnection()
}

// HasEnoughParticipants returns true iff
// nTrustees >= 1 & nClients >= 1
func (s *ServiceState) HasEnoughParticipants() bool {
	t, c := s.churnHandler.CountParticipants()
	return (t >= 1) && (c >= 1)
}

// CountParticipants returns ntrustees, nclients already connected
func (s *ServiceState) CountParticipants() (int, int) {
	return s.churnHandler.CountParticipants()
}

// startPriFi starts a PriFi protocol. It is called
// by the relay as soon as enough participants are
// ready (one trustee and two clients).
func (s *ServiceState) StartPriFiCommunicateProtocol() {
	log.Lvl1("Starting PriFi protocol")

	if s.role != prifi_protocol.Relay {
		log.Error("Trying to start PriFi protocol from a non-relay node.")
		return
	}

	timing.StartMeasure("resync")
	timing.StartMeasure("resync-boot")

	var wrapper *prifi_protocol.PriFiSDAProtocol
	roster := s.churnHandler.createRoster()

	// Start the PriFi protocol on a flat tree with the relay as root
	tree := roster.GenerateNaryTreeWithRoot(100, s.churnHandler.relayIdentity)
	pi, err := s.CreateProtocol(prifi_protocol.ProtocolName, tree)

	if err != nil {
		log.Fatal("Unable to start Prifi protocol:", err)
	}

	// Assert that pi has type PriFiSDAWrapper
	wrapper = pi.(*prifi_protocol.PriFiSDAProtocol)

	//assign and start the protocol
	s.PriFiSDAProtocol = wrapper

	s.setConfigToPriFiProtocol(wrapper)

	wrapper.Start()
}

// stopPriFi stops the PriFi protocol currently running.
func (s *ServiceState) StopPriFiCommunicateProtocol() {
	log.Lvl1("Stopping PriFi protocol")

	if !s.IsPriFiProtocolRunning() {
		log.Lvl3("Would stop PriFi protocol, but it's not running.")
		return
	}

	if s.PriFiSDAProtocol != nil {
		s.PriFiSDAProtocol.Stop()
	}
	s.PriFiSDAProtocol = nil
}

// TODO : change function comment
// autoConnect sends a connection request to the relay
// every 10 seconds if the node is not participating to
// a PriFi protocol.
func (s *ServiceState) connectToTrustees(trusteesIDs []*network.ServerIdentity, stopChan chan bool) {
	for _, v := range trusteesIDs {
		s.sendHelloMessage(v)
	}

	tick := time.Tick(DELAY_BEFORE_CONNECT_TO_TRUSTEES)
	for range tick {
		if !s.IsPriFiProtocolRunning() {
			for _, v := range trusteesIDs {
				s.sendHelloMessage(v)
			}
		}

		select {
		case <-stopChan:
			log.Lvl3("Stopping connectToTrustees subroutine.")
			return
		default:
		}
	}
}

// connectToRelay sends a connection request to the relay
// every 10 seconds if the node is not participating to
// a PriFi protocol.
func (s *ServiceState) connectToRelay(relayID *network.ServerIdentity, stopChan chan bool) {
	s.sendConnectionRequest(relayID)

	tick := time.Tick(DELAY_BEFORE_CONNECT_TO_RELAY)
	for range tick {
		//log.Info("Service", s, ": Still pinging relay", !s.IsPriFiProtocolRunning())
		if !s.IsPriFiProtocolRunning() {
			s.sendConnectionRequest(relayID)
		}

		select {
		case <-stopChan:
			log.Lvl3("Stopping connectToRelay subroutine.")
			return
		default:
		}
	}
}

// sendConnectionRequest sends a connection request to the relay.
// It is called by the client and trustee services at startup to
// announce themselves to the relay.
func (s *ServiceState) sendConnectionRequest(relayID *network.ServerIdentity) {
	log.Lvl4("Sending connection request", s.role, s)
	err := s.SendRaw(relayID, &ConnectionRequest{ProtocolVersion: s.prifiTomlConfig.ProtocolVersion})

	if err != nil {
		if s.role == prifi_protocol.Trustee {
			log.Lvl3("Connection to relay failed. (I'm a client at address", s, ")")
		} else {
			log.Lvl3("Connection to relay failed. (I'm a trustee at address", s, ")")

		}
	}
}

// sendHelloMessage sends a hello message to the trustee.
// It is called by the relay services at startup to
// announce themselves to the trustees.
func (s *ServiceState) sendHelloMessage(trusteeID *network.ServerIdentity) {
	log.Lvl4("Sending hello request", s.role, s)
	err := s.SendRaw(trusteeID, &HelloMsg{})

	if err != nil {
		log.Lvl3("Hello failed, ", trusteeID, " isn't online.", s.role, s)
	}
}
