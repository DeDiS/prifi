package relay

import (
	"errors"
	"github.com/lbarman/prifi/config"
	prifilog "github.com/lbarman/prifi/log"
	prifinet "github.com/lbarman/prifi/net"
	"net"
	"strconv"
	"time"
	"github.com/lbarman/prifi/auth"
)

func initRelayState(nodeConfig config.NodeConfig, relayPort string, nTrustees int, nClients int, upstreamCellSize int, downstreamCellSize int, windowSize int, useDummyDataDown bool, reportingLimit int, trusteesHosts []string, useUDP bool) *RelayState {

	relayState := new(RelayState)

	relayState.Name = nodeConfig.Name
	relayState.RelayPort = relayPort
	relayState.UpstreamCellSize = upstreamCellSize
	relayState.DownstreamCellSize = downstreamCellSize
	relayState.WindowSize = windowSize
	relayState.ReportingLimit = reportingLimit
	relayState.UseUDP = useUDP
	relayState.UseDummyDataDown = useDummyDataDown

	// Generate own parameters
	relayState.privateKey = nodeConfig.PrivateKey
	relayState.PublicKey = nodeConfig.PublicKey

	relayState.nClients = nClients
	relayState.nTrustees = nTrustees
	relayState.trusteesHosts = trusteesHosts
	relayState.PublicKeyRoster = nodeConfig.PublicKeyRoster

	relayState.CellCoder = config.Factory()
	relayState.AuthMethod = nodeConfig.AuthMethod
	return relayState
}

func (relayState *RelayState) deepClone() *RelayState {
	newRelayState := new(RelayState)

	newRelayState.Name = relayState.Name
	newRelayState.RelayPort = relayState.RelayPort
	newRelayState.PublicKey = relayState.PublicKey
	newRelayState.privateKey = relayState.privateKey
	newRelayState.nClients = relayState.nClients
	newRelayState.nTrustees = relayState.nTrustees

	newRelayState.CellCoder = relayState.CellCoder.Clone()

	if relayState.DownstreamHistory.CipherState != nil {
		newRelayState.DownstreamHistory = relayState.DownstreamHistory.Clone()
	}

	newRelayState.UpstreamCellSize = relayState.UpstreamCellSize
	newRelayState.DownstreamCellSize = relayState.DownstreamCellSize
	newRelayState.WindowSize = relayState.WindowSize
	newRelayState.ReportingLimit = relayState.ReportingLimit
	newRelayState.UseUDP = relayState.UseUDP
	newRelayState.UseDummyDataDown = relayState.UseDummyDataDown
	newRelayState.UDPBroadcastConn = relayState.UDPBroadcastConn

	newRelayState.trusteesHosts = make([]string, len(relayState.trusteesHosts))
	copy(newRelayState.trusteesHosts, relayState.trusteesHosts)

	newRelayState.clients = make([]prifinet.NodeRepresentation, len(relayState.clients))
	for i := 0; i < len(relayState.clients); i++ {
		newRelayState.clients[i] = relayState.clients[i].Clone()
	}

	newRelayState.trustees = make([]prifinet.NodeRepresentation, len(relayState.trustees))
	for i := 0; i < len(relayState.trustees); i++ {
		newRelayState.trustees[i] = relayState.trustees[i].Clone()
	}
	return newRelayState
}

func (relayState *RelayState) addNewClient(newClient prifinet.NodeRepresentation) {
	relayState.nClients = relayState.nClients + 1
	relayState.clients = append(relayState.clients, newClient)
}

func connectToTrusteeAsync(trusteeChan chan prifinet.NodeRepresentation, id int, host string, relayState *RelayState) {

	var err error = errors.New("empty")
	trustee := prifinet.NodeRepresentation{}

	for i := 0; i < config.NUM_RETRY_CONNECT && err != nil; i++ {
		trustee, err = connectToTrustee(host, relayState)

		if err != nil {
			prifilog.Println(prifilog.RECOVERABLE_ERROR, "Failed to connect to trustee "+strconv.Itoa(id)+" host "+host+", retrying after two second...")
			time.Sleep(2 * time.Second)
		}
	}

	if err == nil {
		trusteeChan <- trustee
	}
	prifilog.Println(prifilog.RECOVERABLE_ERROR, "Cannot connect to the trustee.")
}

func (relayState *RelayState) connectToAllTrustees() {

	defer prifilog.TimeTrack("relay", "connectToAllTrustees", time.Now())

	trusteeChan := make(chan prifinet.NodeRepresentation, relayState.nTrustees)

	// Connect to all the trustees
	for i := 0; i < relayState.nTrustees; i++ {
		go connectToTrusteeAsync(trusteeChan, i, relayState.trusteesHosts[i], relayState)
	}

	// Wait for all the trustees to be connected
	i := 0
	for i < relayState.nTrustees {
		select {
		case trustee := <-trusteeChan:
			relayState.trustees = append(relayState.trustees, trustee)
			i++

		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	prifilog.Println(prifilog.INFORMATION, "Trustee connected,", len(relayState.trustees), "trustees connected")
}

func (relayState *RelayState) disconnectFromAllTrustees() {
	defer prifilog.TimeTrack("relay", "disconnectToAllTrustees", time.Now())

	//disconnect to the trustees
	for i := 0; i < len(relayState.trustees); i++ {
		relayState.trustees[i].Conn.Close()
	}
	relayState.trustees = make([]prifinet.NodeRepresentation, 0)
	prifilog.Println(prifilog.INFORMATION, "Trustees disonnecting done, ", len(relayState.trustees), "trustees disconnected")
}

func welcomeNewClients(newConnectionsChan chan net.Conn, newClientChan chan prifinet.NodeRepresentation, clientsUseUDP bool, authMethod int) {

	newClientsToParse := make(chan prifinet.NodeRepresentation)

	for {
		select {
		// Accept the TCP connection and authenticate the client
		case newConnection := <-newConnectionsChan:
			go func() {
				// Authenticate the client
				newClient, err := auth.ServerAuthentication(authMethod, newConnection, relayState.PublicKeyRoster)

				if err == nil {
					prifilog.Println(prifilog.INFORMATION, "Client "+strconv.Itoa(newClient.Id)+" authenticated successfully.")
					newClientsToParse <- newClient
				} else {
					prifilog.Println(prifilog.WARNING, "Client "+strconv.Itoa(newClient.Id)+" authentication failed.")
				}
			}()

		// Once client is ready, forward to the other channel
		case newClient := <-newClientsToParse:
			newClientChan <- newClient

		default:
			time.Sleep(NEWCLIENT_CHECK_SLEEP_TIME) //todo : check this duration
		}
	}
}

func (relayState *RelayState) waitForDefaultNumberOfClients(newClientConnectionsChan chan prifinet.NodeRepresentation) {
	defer prifilog.TimeTrack("relay", "waitForDefaultNumberOfClients", time.Now())

	currentClients := 0

	prifilog.Printf(prifilog.INFORMATION, "Waiting for %d clients (on port %s)", relayState.nClients-currentClients, relayState.RelayPort)

	for currentClients < relayState.nClients {
		select {
		case newClient := <-newClientConnectionsChan:
			relayState.clients = append(relayState.clients, newClient)
			currentClients += 1
			prifilog.Printf(prifilog.INFORMATION, "Waiting for %d clients (on port %s)", relayState.nClients-currentClients, relayState.RelayPort)
		default:
			time.Sleep(100 * time.Millisecond)
			//prifilog.StatisticReport("relay", "SLEEP_100ms", "100ms")
		}
	}
	prifilog.Println(prifilog.INFORMATION, "Client connected,", len(relayState.clients), "clients connected")
}

func (relayState *RelayState) excludeDisconnectedClients() {
	defer prifilog.TimeTrack("relay", "excludeDisconnectedClients", time.Now())

	//count the clients that disconnected
	nClientsDisconnected := 0
	for i := 0; i < len(relayState.clients); i++ {
		if !relayState.clients[i].Connected {
			prifilog.Println(prifilog.INFORMATION, "Relay Handler : Client ", i, " discarded, seems he disconnected...")
			nClientsDisconnected++
		}
	}

	//count the actual number of clients, and init the new state with the old parameters
	newNClients := relayState.nClients - nClientsDisconnected

	//copy the connected clients
	newClients := make([]prifinet.NodeRepresentation, newNClients)
	j := 0
	for i := 0; i < len(relayState.clients); i++ {
		if relayState.clients[i].Connected {
			newClients[j] = relayState.clients[i]
			prifilog.Println(prifilog.INFORMATION, "Adding Client ", i, "who's not disconnected")
			j++
		}
	}

	relayState.clients = newClients
}
