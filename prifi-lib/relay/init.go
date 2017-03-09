package relay

/*
PriFi Relay
************
This regroups the behavior of the PriFi relay.
Needs to be instantiated via the PriFiProtocol in prifi.go
Then, this file simple handle the answer to the different message kind :

- ALL_ALL_SHUTDOWN - kill this relay
- ALL_ALL_PARAMETERS (specialized into ALL_REL_PARAMETERS) - used to initialize the relay over the network / overwrite its configuration
- TRU_REL_TELL_PK - when a trustee connects, he tells us his public key
- CLI_REL_TELL_PK_AND_EPH_PK - when they receive the list of the trustees, each clients tells his identity. when we have all client's IDs,
								  we send them to the trustees to shuffle (Schedule protocol)
- TRU_REL_TELL_NEW_BASE_AND_EPH_PKS - when we receive the result of one shuffle, we forward it to the next trustee
- TRU_REL_SHUFFLE_SIG - when the shuffle has been done by all trustee, we send the transcript, and they answer with a signature, which we
						   broadcast to the clients
- CLI_REL_UPSTREAM_DATA - data for the DC-net
- REL_CLI_UDP_DOWNSTREAM_DATA - is NEVER received here, but casted to CLI_REL_UPSTREAM_DATA by messages.go
- TRU_REL_DC_CIPHER - data for the DC-net

local functions :

ConnectToTrustees() - simple helper
finalizeUpstreamData() - called after some Receive_CLI_REL_UPSTREAM_DATA, when we have all ciphers.
sendDownstreamData() - called after a finalizeUpstreamData(), to continue the communication
checkIfRoundHasEndedAfterTimeOut_Phase1() - called by sendDownstreamData(), which starts a new round. After some short time, if the round hasn't changed, and we used UDP,
											   retransmit messages to client over TCP
checkIfRoundHasEndedAfterTimeOut_Phase2() - called by checkIfRoundHasEndedAfterTimeOut_Phase1(). After some long time, entities that didn't send us data should be
considered disconnected

*/

import (
	"errors"
	"time"

	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/dcnet"
	prifilog "github.com/lbarman/prifi/prifi-lib/log"
	"github.com/lbarman/prifi/prifi-lib/net"
	"github.com/lbarman/prifi/prifi-lib/scheduler"
	"github.com/lbarman/prifi/prifi-lib/utils"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"

	"github.com/lbarman/prifi/prifi-lib/crypto"
	"reflect"
	"strings"
)

// PriFiLibInstance contains the mutable state of a PriFi entity.
type PriFiLibRelayInstance struct {
	messageSender *net.MessageSenderWrapper
	relayState    *RelayState
	stateMachine  *utils.StateMachine
}

// NewPriFiRelay creates a new PriFi relay entity state.
// Note: the returned state is not sufficient for the PrFi protocol
// to start; this entity will expect a ALL_ALL_PARAMETERS message as
// first received message to complete it's state.
func NewRelay(dataOutputEnabled bool, dataForClients chan []byte, dataFromDCNet chan []byte, experimentResultChan chan interface{}, timeoutHandler func([]int, []int), msgSender *net.MessageSenderWrapper) *PriFiLibRelayInstance {
	relayState := new(RelayState)

	//init the static stuff
	relayState.CellCoder = config.Factory()
	relayState.DataForClients = dataForClients
	relayState.DataFromDCNet = dataFromDCNet
	relayState.DataOutputEnabled = dataOutputEnabled
	relayState.timeoutHandler = timeoutHandler
	relayState.ExperimentResultChannel = experimentResultChan
	relayState.ExperimentResultData = make([]string, 0)
	relayState.PriorityDataForClients = make(chan []byte, 10) // This is used for relay's control message (like latency-tests)
	relayState.bitrateStatistics = prifilog.NewBitRateStatistics()
	relayState.timeStatistics = make(map[string]*prifilog.TimeStatistics)
	relayState.timeStatistics["round-duration"] = prifilog.NewTimeStatistics()
	relayState.timeStatistics["waiting-on-clients"] = prifilog.NewTimeStatistics()
	relayState.timeStatistics["waiting-on-trustees"] = prifilog.NewTimeStatistics()
	relayState.timeStatistics["sending-data"] = prifilog.NewTimeStatistics()
	relayState.PublicKey, relayState.privateKey = crypto.NewKeyPair()
	relayState.bufferManager = new(BufferManager)
	neffShuffle := new(scheduler.NeffShuffle)
	neffShuffle.Init()
	relayState.neffShuffle = neffShuffle.RelayView
	relayState.Name = "Relay"

	//init the state machine
	states := []string{"BEFORE_INIT", "COLLECTING_TRUSTEES_PKS", "COLLECTING_CLIENT_PKS", "COLLECTING_SHUFFLES", "COLLECTING_SHUFFLE_SIGNATURES", "COMMUNICATING", "SHUTDOWN"}
	sm := new(utils.StateMachine)
	logFn := func(s interface{}) {
		log.Lvl2(s)
	}
	errFn := func(s interface{}) {
		if strings.Contains(s.(string), ", but in state SHUTDOWN") { //it's an "acceptable error"
			log.Lvl2(s)
		} else {
			log.Error(s)
		}
	}
	sm.Init(states, logFn, errFn)

	prifi := PriFiLibRelayInstance{
		messageSender: msgSender,
		relayState:    relayState,
		stateMachine:  sm,
	}
	return &prifi
}

//The time slept between each round
const PROCESSING_LOOP_SLEEP_TIME = 0 * time.Millisecond

//The timeout before retransmission. Here of 0, since we have only TCP. to be increase with UDP
const TIMEOUT_PHASE_1 = 2 * time.Second

//The timeout before kicking a client/trustee
const TIMEOUT_PHASE_2 = 3 * time.Second

// Number of ciphertexts buffered by trustees. When <= TRUSTEE_CACHE_LOWBOUND, resume sending
const TRUSTEE_CACHE_LOWBOUND = 1

// Number of ciphertexts buffered by trustees. When >= TRUSTEE_CACHE_HIGHBOUND, stop sending
const TRUSTEE_CACHE_HIGHBOUND = 10

// NodeRepresentation regroups the information about one client or trustee.
type NodeRepresentation struct {
	ID                 int
	Connected          bool
	PublicKey          abstract.Point
	EphemeralPublicKey abstract.Point
}

// RelayState contains the mutable state of the relay.
type RelayState struct {
	bufferManager                     *BufferManager
	CellCoder                         dcnet.CellCoder
	clients                           []NodeRepresentation
	dcnetRoundManager                 *DCNetRoundManager
	neffShuffle                       *scheduler.NeffShuffleRelay
	currentState                      int16
	DataForClients                    chan []byte // VPN / SOCKS should put data there !
	PriorityDataForClients            chan []byte
	DataFromDCNet                     chan []byte // VPN / SOCKS should read data from there !
	DataOutputEnabled                 bool        // If FALSE, nothing will be written to DataFromDCNet
	DownstreamCellSize                int
	MessageHistory                    abstract.Cipher
	Name                              string
	nClients                          int
	nClientsPkCollected               int
	nTrustees                         int
	nTrusteesPkCollected              int
	privateKey                        abstract.Scalar
	PublicKey                         abstract.Point
	ExperimentRoundLimit              int
	trustees                          []NodeRepresentation
	UpstreamCellSize                  int
	UseDummyDataDown                  bool
	UseUDP                            bool
	numberOfNonAckedDownstreamPackets int
	WindowSize                        int
	nextDownStreamRoundToSend         int32
	ExperimentResultChannel           chan interface{}
	ExperimentResultData              []string
	timeoutHandler                    func([]int, []int)
	bitrateStatistics                 *prifilog.BitrateStatistics
	timeStatistics                    map[string]*prifilog.TimeStatistics
}

// ReceivedMessage must be called when a PriFi host receives a message.
// It takes care to call the correct message handler function.
func (p *PriFiLibRelayInstance) ReceivedMessage(msg interface{}) error {

	var err error

	switch typedMsg := msg.(type) {
	case net.ALL_ALL_PARAMETERS_NEW:
		if typedMsg.ForceParams || p.stateMachine.AssertState("BEFORE_INIT") {
			err = p.Received_ALL_ALL_PARAMETERS(typedMsg)
		}
	case net.ALL_ALL_SHUTDOWN:
		err = p.Received_ALL_ALL_SHUTDOWN(typedMsg)
	case net.CLI_REL_UPSTREAM_DATA:
		if p.stateMachine.AssertState("COMMUNICATING") {
			err = p.Received_CLI_REL_UPSTREAM_DATA(typedMsg)
		}
	case net.TRU_REL_DC_CIPHER:
		if p.stateMachine.AssertStateOrState("COMMUNICATING", "COLLECTING_SHUFFLE_SIGNATURES") {
			err = p.Received_TRU_REL_DC_CIPHER(typedMsg)
		}
	case net.TRU_REL_TELL_PK:
		if p.stateMachine.AssertState("COLLECTING_TRUSTEES_PKS") {
			err = p.Received_TRU_REL_TELL_PK(typedMsg)
		}
	case net.CLI_REL_TELL_PK_AND_EPH_PK:
		if p.stateMachine.AssertState("COLLECTING_CLIENT_PKS") {
			err = p.Received_CLI_REL_TELL_PK_AND_EPH_PK(typedMsg)
		}
	case net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS:
		if p.stateMachine.AssertState("COLLECTING_SHUFFLES") {
			err = p.Received_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS(typedMsg)
		}
	case net.TRU_REL_SHUFFLE_SIG:
		if p.stateMachine.AssertState("COLLECTING_SHUFFLE_SIGNATURES") {
			err = p.Received_TRU_REL_SHUFFLE_SIG(typedMsg)
		}
	default:
		err = errors.New("Unrecognized message, type" + reflect.TypeOf(msg).String())
	}

	return err
}
