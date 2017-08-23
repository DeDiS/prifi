package protocols

import (
	"errors"
	"strconv"

	"github.com/lbarman/prifi/prifi-lib/net"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

//MessageSender is the struct we need to give PriFi-Lib so it can send messages.
//It needs to implement the "MessageSender interface" defined in prifi_lib/prifi.go
type MessageSender struct {
	tree       *onet.TreeNodeInstance
	relay      *onet.TreeNode
	clients    map[int]*onet.TreeNode
	trustees   map[int]*onet.TreeNode
	udpChannel UDPChannel
}

// buildMessageSender creates a MessageSender struct
// given a mep between server identities and PriFi identities.
func (p *PriFiSDAProtocol) buildMessageSender(identities map[string]PriFiIdentity) MessageSender {
	nodes := p.List() // Has type []*onet.TreeNode
	trustees := make(map[int]*onet.TreeNode)
	clients := make(map[int]*onet.TreeNode)
	trusteeID := 0
	clientID := 0
	var relay *onet.TreeNode

	for i := 0; i < len(nodes); i++ {
		identifier := nodes[i].ServerIdentity.Public.String()
		id, ok := identities[identifier]
		port, _ := strconv.Atoi(nodes[i].ServerIdentity.Address.Port())
		portForFastChannel := port + 3

		log.Lvl3("Found identity", identifier, " -> ", port, portForFastChannel)

		if !ok {
			log.Lvl3("Skipping unknow node with address", identifier)
			continue
		}
		switch id.Role {
		case Client:
			clients[clientID] = nodes[i] //TODO : wrong
			clientID++
		case Trustee:
			trustees[trusteeID] = nodes[i]
			trusteeID++
		case Relay:
			if relay == nil {
				relay = nodes[i]
			} else {
				log.Fatal("Multiple relays")
			}
		}
	}

	return MessageSender{p.TreeNodeInstance, relay, clients, trustees, newRealUDPChannel()}
}

//SendToClient sends a message to client i, or fails if it is unknown
func (ms MessageSender) FastSendToClient(i int, msg *net.REL_CLI_DOWNSTREAM_DATA) error {

	if client, ok := ms.clients[i]; ok {
		log.Lvl5("Sending a message to client ", i, " (", client.Name(), ") - ", msg)
		return ms.tree.SendTo(client, msg)
	}

	e := "Client " + strconv.Itoa(i) + " is unknown !"
	log.Error(e)
	return errors.New(e)
}

//SendToRelay sends a message to the unique relay
func (ms MessageSender) FastSendToRelay(msg *net.CLI_REL_UPSTREAM_DATA) error {
	log.Lvl5("Sending a message to relay ", " - ", msg)
	return ms.tree.SendTo(ms.relay, msg)
}

//SendToClient sends a message to client i, or fails if it is unknown
func (ms MessageSender) SendToClient(i int, msg interface{}) error {

	if client, ok := ms.clients[i]; ok {
		log.Lvl5("Sending a message to client ", i, " (", client.Name(), ") - ", msg)
		return ms.tree.SendTo(client, msg)
	}

	e := "Client " + strconv.Itoa(i) + " is unknown !"
	log.Error(e)
	return errors.New(e)
}

//SendToTrustee sends a message to trustee i, or fails if it is unknown
func (ms MessageSender) SendToTrustee(i int, msg interface{}) error {

	if trustee, ok := ms.trustees[i]; ok {
		log.Lvl5("Sending a message to trustee ", i, " (", trustee.Name(), ") - ", msg)
		return ms.tree.SendTo(trustee, msg)
	}

	e := "Trustee " + strconv.Itoa(i) + " is unknown !"
	log.Error(e)
	return errors.New(e)
}

//SendToRelay sends a message to the unique relay
func (ms MessageSender) SendToRelay(msg interface{}) error {
	log.Lvl5("Sending a message to relay ", " - ", msg)
	return ms.tree.SendTo(ms.relay, msg)
}

//BroadcastToAllClients broadcasts a message (must be a REL_CLI_DOWNSTREAM_DATA_UDP) to all clients using UDP
func (ms MessageSender) BroadcastToAllClients(msg interface{}) error {

	castedMsg, canCast := msg.(*net.REL_CLI_DOWNSTREAM_DATA_UDP)
	if !canCast {
		log.Error("Message sender : could not cast msg to REL_CLI_DOWNSTREAM_DATA_UDP, and I don't know how to send other messages.")
	}
	ms.udpChannel.Broadcast(castedMsg)

	return nil
}

//ClientSubscribeToBroadcast allows a client to subscribe to UDP broadcast
func (ms MessageSender) ClientSubscribeToBroadcast(clientID int, messageReceived func(interface{}) error, startStopChan chan bool) error {

	clientName := "client-" + strconv.Itoa(clientID)
	log.Lvl3(clientName, " started UDP-listener helper.")
	listening := false
	lastSeenMessage := 0 //the first real message has ID 1; this means that we saw the empty struct.

	for {
		select {
		case val := <-startStopChan:
			if val {
				listening = true //either we listen or we stop
				log.Lvl3("client", clientName, " switched on broadcast-listening")
			} else {
				log.Lvl3("client", clientName, " killed broadcast-listening.")
				return nil
			}
		default:
		}

		if listening {
			emptyMessage := net.REL_CLI_DOWNSTREAM_DATA_UDP{}
			//listen and decode
			log.Lvl4("client", clientName, " calling listen and block...")
			filledMessage, err := ms.udpChannel.ListenAndBlock(&emptyMessage, lastSeenMessage, clientName)
			lastSeenMessage++

			if err != nil {
				log.Error(clientName, " an error occurred : ", err)
			}

			log.Lvl4(clientName, " Received an UDP message n°"+strconv.Itoa(lastSeenMessage))

			if err != nil {
				log.Error(clientName, " an error occurred : ", err)
			}

			messageReceived(filledMessage)

		}
	}
}
