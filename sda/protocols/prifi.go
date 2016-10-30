package prifi

/*
 * PRIFI SDA WRAPPER
 *
 * Caution : this is not the "PriFi protocol", which is really a "PriFi Library" which you need to import, and feed with some network methods.
 * This is the "PriFi-SDA-Wrapper" protocol, which imports the PriFi lib, gives it "SendToXXX()" methods and calls the "prifi_library.MessageReceived()"
 * methods (it build a map that converts the SDA tree into identities), and starts the PriFi Library.
 */

import (
	"errors"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/sda"
	prifi_lib "github.com/lbarman/prifi_dev/prifi-lib"
)

//the UDP channel we provide to PriFi. check udp.go for more details.
var udpChan UDPChannel = newRealUDPChannel()// Cannot use localhost channel anymore for real deployment

type PriFiRole int

const (
	Relay PriFiRole = iota
	Client
	Trustee
)

type PriFiIdentity struct {
	Role PriFiRole
	Id int
}

type PriFiSDAWrapperConfig struct {
	prifi_lib.ALL_ALL_PARAMETERS
	Identities map[network.ServerIdentity]PriFiIdentity
	Role PriFiRole
}

//This is the PriFi-SDA-Wrapper protocol struct. It contains the SDA-tree, and a chanel that stops the simulation when it receives a "true"
type PriFiSDAWrapper struct {
	*sda.TreeNodeInstance
	configSet     bool
	config        PriFiSDAWrapperConfig
	ResultChannel chan interface{}

	//this is the actual "PriFi" (DC-net) protocol/library, defined in prifi-lib/prifi.go
	prifiProtocol *prifi_lib.PriFiProtocol
}

//the "PriFi-Wrapper-Protocol start". It calls the PriFi library with the correct parameters
func (p *PriFiSDAWrapper) Start() error {

	if !p.configSet {
		log.Error("Trying to start PriFi Library, but config not set !")
	}

	log.Lvl3("Starting PriFi-SDA-Wrapper Protocol")

	//print the network host map
	nTrustees := tomlConfig.NTrustees
	nodes := p.TreeNodeInstance.List()
	log.Lvl2("Relay      -> ", nodes[0].Name())
	for i := 1; i < nTrustees+1; i++ {
		log.Lvl2("Trustee", (i - 1), " -> ", nodes[i].Name())
	}
	for i := 1 + nTrustees; i < len(nodes); i++ {
		log.Lvl2("Client ", (i - nTrustees - 1), " -> ", nodes[i].Name())
	}

	//simulate the first message received (here the parameters). If StartNow = true, the relay will handle the situation from now on
	configMessageWrapper := Struct_ALL_ALL_PARAMETERS{p.TreeNode(), p.config}
	_ = p.Received_ALL_ALL_PARAMETERS(configMessageWrapper)

	//initialize the first message (here the dummy ping-pong game)
	//firstMessage := &prifi_lib.CLI_REL_UPSTREAM_DATA{100, make([]byte, 0)}
	//firstMessageWrapper := Struct_CLI_REL_UPSTREAM_DATA{p.TreeNode(), *firstMessage}
	//_ = p.Received_CLI_REL_UPSTREAM_DATA(firstMessageWrapper)

	return nil
}

/**
 * On initialization of the PriFi-SDA-Wrapper protocol, it need to register the PriFi-Lib messages to be able to marshall them.
 * If we forget some messages there, it will crash when PriFi-Lib will call SendToXXX() with this message !
 */
func init() {

	//register the prifi_lib's message with the network lib here
	network.RegisterPacketType(prifi_lib.ALL_ALL_PARAMETERS{})
	network.RegisterPacketType(prifi_lib.CLI_REL_TELL_PK_AND_EPH_PK{})
	network.RegisterPacketType(prifi_lib.CLI_REL_UPSTREAM_DATA{})
	network.RegisterPacketType(prifi_lib.REL_CLI_DOWNSTREAM_DATA{})
	network.RegisterPacketType(prifi_lib.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG{})
	network.RegisterPacketType(prifi_lib.REL_CLI_TELL_TRUSTEES_PK{})
	network.RegisterPacketType(prifi_lib.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE{})
	network.RegisterPacketType(prifi_lib.REL_TRU_TELL_TRANSCRIPT{})
	network.RegisterPacketType(prifi_lib.TRU_REL_DC_CIPHER{})
	network.RegisterPacketType(prifi_lib.REL_TRU_TELL_RATE_CHANGE{})
	network.RegisterPacketType(prifi_lib.TRU_REL_SHUFFLE_SIG{})
	network.RegisterPacketType(prifi_lib.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS{})
	network.RegisterPacketType(prifi_lib.TRU_REL_TELL_PK{})

	sda.GlobalProtocolRegister("PriFi-SDA-Wrapper", NewPriFiSDAWrapperProtocol)
}

func (p *PriFiSDAWrapper) SetConfig(config PriFiSDAWrapperConfig) {
	p.config = config
	p.configSet = true
	log.Lvl2("Setting PriFi config to be : ", config)
}

/**
 * This function is called on all nodes of the SDA-tree (when they receive their first prifi message).
 * It build a network map (deterministic from the order of the tree), which allows to build the
 * messageSender struct needed by PriFi-Lib.
 * Then, it instantiate PriFi-Lib with the correct state, given the role of the node.
 * Finally, it registers handlers so it can unmarshal messages and give them back to prifi. It is kind of ridiculous to have a handler for each
 * message, as PriFi-Lib is able to recognize the messages (everything is fed to ReceivedMessage() in PriFi-Lib), but that is how the SDA works
 * for now.
 */
func NewPriFiSDAWrapperProtocol(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {

	//fill in the network host map
	nTrustees := tomlConfig.NTrustees
	nodes := n.List()
	nodeRelay := nodes[0]
	nodesTrustee := make(map[int]*sda.TreeNode)
	for i := 1; i < nTrustees+1; i++ {
		nodesTrustee[i-1] = nodes[i]
	}
	nodesClient := make(map[int]*sda.TreeNode)
	for i := 1 + nTrustees; i < len(nodes); i++ {
		nodesClient[i-1-nTrustees] = nodes[i]
	}
	messageSender := MessageSender{n, nodeRelay, nodesClient, nodesTrustee}

	//parameters goes there
	nClients := tomlConfig.NClients //my eyes are bleeding. Sorry for this part
	upCellSize := tomlConfig.CellSizeUp
	downCellSize := tomlConfig.CellSizeDown
	relayWindowSize := tomlConfig.RelayWindowSize
	relayUseDummyDataDown := tomlConfig.RelayUseDummyDataDown
	relayReportingLimit := tomlConfig.RelayReportingLimit
	useUDP := tomlConfig.UseUDP
	doLatencyTests := tomlConfig.DoLatencyTests
	sendDataOutOfDCNet := false

	var prifiProtocol *prifi_lib.PriFiProtocol
	experimentResultChan := make(chan interface{}, 1)

	//first of all, instantiate our prifi library with the correct role, given our position in the tree
	if n.Index() == 0 {
		log.Print(n.Name(), " starting as a PriFi relay")
		relayState := prifi_lib.NewRelayState(nTrustees, nClients, upCellSize, downCellSize, relayWindowSize, relayUseDummyDataDown, relayReportingLimit, experimentResultChan, useUDP, sendDataOutOfDCNet)
		prifiProtocol = prifi_lib.NewPriFiRelayWithState(messageSender, relayState)
	} else if n.Index() > 0 && n.Index() <= nTrustees {
		trusteeId := n.Index() - 1
		log.Print(n.Name(), " starting as PriFi trustee", trusteeId)
		trusteeState := prifi_lib.NewTrusteeState(trusteeId, nTrustees, nClients, upCellSize)
		prifiProtocol = prifi_lib.NewPriFiTrusteeWithState(messageSender, trusteeState)
	} else {
		clientId := (n.Index() - nTrustees - 1)
		log.Print(n.Name(), " starting as a PriFi client", clientId)
		clientState := prifi_lib.NewClientState(clientId, nTrustees, nClients, upCellSize, doLatencyTests, useUDP, sendDataOutOfDCNet)
		prifiProtocol = prifi_lib.NewPriFiClientWithState(messageSender, clientState)
	}

	//instantiate our PriFi wrapper protocol
	prifiSDAWrapperHandlers := &PriFiSDAWrapper{
		TreeNodeInstance: n,
		ResultChannel:    experimentResultChan,
		prifiProtocol:    prifiProtocol,
	}

	//register handlers
	err := prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_ALL_ALL_PARAMETERS)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_ALL_ALL_SHUTDOWN)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}

	//register client handlers
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_REL_CLI_DOWNSTREAM_DATA)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_REL_CLI_TELL_TRUSTEES_PK)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}

	//register relay handlers
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_CLI_REL_TELL_PK_AND_EPH_PK)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_CLI_REL_UPSTREAM_DATA)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_TRU_REL_DC_CIPHER)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_TRU_REL_SHUFFLE_SIG)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_TRU_REL_TELL_PK)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}

	//register trustees handlers
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_REL_TRU_TELL_TRANSCRIPT)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}
	err = prifiSDAWrapperHandlers.RegisterHandler(prifiSDAWrapperHandlers.Received_REL_TRU_TELL_RATE_CHANGE)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}

	return prifiSDAWrapperHandlers, nil
}
