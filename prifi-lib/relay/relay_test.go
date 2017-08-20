package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/lbarman/prifi/prifi-lib/client"
	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/crypto"
	"github.com/lbarman/prifi/prifi-lib/net"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/log"
	"strconv"
	"sync"
	"testing"
	"time"
)

/**
 * Message Sender
 */
type TestMessageSender struct {
}

var clientLock sync.Mutex
var trusteeLock sync.Mutex

func (t *TestMessageSender) SendToClient(i int, msg interface{}) error {
	clientLock.Lock()
	defer clientLock.Unlock()
	sentToClient = append(sentToClient, msg)
	return nil
}
func (t *TestMessageSender) SendToTrustee(i int, msg interface{}) error {
	trusteeLock.Lock()
	defer trusteeLock.Unlock()
	sentToTrustee = append(sentToTrustee, msg)
	return nil
}

var sentToClient []interface{}
var sentToTrustee []interface{}

func (t *TestMessageSender) SendToRelay(msg interface{}) error {
	return errors.New("Relay sending to relay !?")
}
func (t *TestMessageSender) BroadcastToAllClients(msg interface{}) error {
	return t.SendToClient(0, msg)
}
func (t *TestMessageSender) ClientSubscribeToBroadcast(clientID int, messageReceived func(interface{}) error, startStopChan chan bool) error {
	return errors.New("Not for relay")
}

/**
 * Message Sender Wrapper
 */

func newTestMessageSenderWrapper(msgSender net.MessageSender) *net.MessageSenderWrapper {

	errHandling := func(e error) {}
	loggingSuccessFunction := func(e interface{}) { log.Lvl3(e) }
	loggingErrorFunction := func(e interface{}) { log.Error(e) }

	msw, err := net.NewMessageSenderWrapper(true, loggingSuccessFunction, loggingErrorFunction, errHandling, msgSender)
	if err != nil {
		log.Fatal("Could not create a MessageSenderWrapper, error is", err)
	}
	return msw
}

func getClientMessage(wantedMessage string) (interface{}, error) {
	clientLock.Lock()
	defer clientLock.Unlock()
	return getMessage(&sentToClient, wantedMessage)
}
func getTrusteeMessage(wantedMessage string) (interface{}, error) {
	trusteeLock.Lock()
	defer trusteeLock.Unlock()
	return getMessage(&sentToTrustee, wantedMessage)
}

func getMessage(bufferPtr *[]interface{}, wantedMessage string) (interface{}, error) {
	buffer := *bufferPtr
	if buffer == nil {
		panic("Buffer nil")
	}
	if len(buffer) == 0 {
		return nil, errors.New("Tried to fetch a " + wantedMessage + "but buffer is empty.")
	}
	msg := buffer[0]
	*bufferPtr = buffer[1:]
	return msg, nil
}

func TestRelayRun1(t *testing.T) {

	timeoutHandler := func(clients, trustees []int) { log.Error(clients, trustees) }
	resultChan := make(chan interface{}, 1)

	msgSender := new(TestMessageSender)
	msw := newTestMessageSenderWrapper(msgSender)
	ocSleep := 1000
	sentToClient = make([]interface{}, 0)
	sentToTrustee = make([]interface{}, 0)
	dataForClients := make(chan []byte, 6)
	dataFromDCNet := make(chan []byte, 3)

	relay := NewRelay(true, dataForClients, dataFromDCNet, resultChan, ocSleep, timeoutHandler, msw)

	//when receiving no message, client should have some parameters ready
	rs := relay.relayState
	if rs.DataOutputEnabled != true {
		t.Error("DataOutputEnabled was not set correctly")
	}
	if rs.DataFromDCNet == nil {
		t.Error("DataFromDCNet was not set correctly")
	}
	if rs.DataForClients == nil {
		t.Error("DataForClients was not set correctly")
	}
	if rs.timeoutHandler == nil {
		t.Error("timeoutHandler was not set correctly")
	}
	if rs.ExperimentResultChannel == nil {
		t.Error("ExperimentResultChannel was not set correctly")
	}
	if rs.PriorityDataForClients == nil {
		t.Error("PriorityDataForClients was not set correctly")
	}
	if relay.stateMachine.State() != "BEFORE_INIT" {
		t.Error("State was not set correctly")
	}
	if rs.privateKey == nil || rs.PublicKey == nil {
		t.Error("Private/Public key not set")
	}
	if rs.bitrateStatistics == nil {
		t.Error("Statistics should have been set")
	}

	//we start by receiving a ALL_ALL_PARAMETERS from relay
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true
	nClients := 1
	nTrustees := 1
	upCellSize := 1500
	dcNetType := "Simple"
	msg.Add("StartNow", true)
	msg.Add("NClients", nClients)
	msg.Add("NTrustees", nTrustees)
	msg.Add("UpstreamCellSize", upCellSize)
	msg.Add("DownstreamCellSize", 10*upCellSize)
	msg.Add("WindowSize", 1)
	msg.Add("UseUDP", true)
	msg.Add("UseDummyDataDown", true)
	msg.Add("ExperimentRoundLimit", 2)
	msg.Add("DCNetType", dcNetType)

	if err := relay.ReceivedMessage(*msg); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}
	if rs.nClients != nClients {
		t.Error("nClients was not set correctly")
	}
	if rs.nTrustees != nTrustees {
		t.Error("nTrustees was not set correctly")
	}
	if rs.nTrusteesPkCollected != 0 {
		t.Error("nTrusteesPkCollected was not set correctly")
	}
	if rs.nClientsPkCollected != 0 {
		t.Error("nClientsPkCollected was not set correctly")
	}
	if rs.ExperimentRoundLimit != 2 {
		t.Error("ExperimentRoundLimit was not set correctly")
	}
	if rs.CellCoder == nil {
		t.Error("CellCoder should have been created")
	}
	if rs.UpstreamCellSize != upCellSize {
		t.Error("UpstreamCellSize was not set correctly")
	}
	if rs.DownstreamCellSize != 10*upCellSize {
		t.Error("DownstreamCellSize was not set correctly")
	}
	if rs.UseDummyDataDown != true {
		t.Error("UseDummyDataDown was not set correctly")
	}
	if rs.UseUDP != true {
		t.Error("UseUDP was not set correctly")
	}
	if rs.roundManager.NextRoundToOpen() != 0 {
		t.Error("nextDownStreamRoundToSend was not set correctly; it should be equal to 0. Is", rs.roundManager.NextRoundToOpen())
	}
	if rs.WindowSize != 1 {
		t.Error("WindowSize was not set correctly")
	}
	if rs.dcNetType != "Simple" {
		t.Error("DCNetType was not set correctly")
	}
	if rs.roundManager.resumeFunction == nil {
		t.Error("bufferManager.resumeFunction was not set correctly")
	}
	if rs.roundManager.stopFunction == nil {
		t.Error("bufferManager.stopFunction was not set correctly")
	}
	if relay.stateMachine.State() != "COLLECTING_TRUSTEES_PKS" {
		t.Error("In wrong state ! we should be in COLLECTING_TRUSTEES_PKS, but are in ", relay.stateMachine.State())
	}

	// should send ALL_ALL_PARAMETERS to clients
	msg2, err := getClientMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	msg3 := msg2.(*net.ALL_ALL_PARAMETERS_NEW)

	if msg3.ParamsInt["NClients"] != nClients {
		t.Error("nClients not set correctly")
	}
	if msg3.ParamsInt["NTrustees"] != nTrustees {
		t.Error("nTrustees not set correctly")
	}
	if msg3.ParamsBool["StartNow"] != true {
		t.Error("StartNow not set correctly")
	}
	if msg3.ParamsInt["UpstreamCellSize"] != upCellSize {
		t.Error("UpstreamCellSize not set correctly")
	}
	if msg3.ParamsInt["NextFreeClientID"] != 0 {
		t.Error("NextFreeTrusteeID not set correctly")
	}
	if msg3.ParamsStr["DCNetType"] != "Simple" {
		t.Error("DCNetType not set correctly")
	}

	// should send ALL_ALL_PARAMETERS to trustees
	msg4, err := getTrusteeMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	msg5 := msg4.(*net.ALL_ALL_PARAMETERS_NEW)

	if msg5.ParamsInt["NClients"] != nClients {
		t.Error("nClients not set correctly")
	}
	if msg5.ParamsInt["NTrustees"] != nTrustees {
		t.Error("nTrustees not set correctly")
	}
	if msg5.ParamsBool["StartNow"] != true {
		t.Error("StartNow not set correctly")
	}
	if msg5.ParamsInt["UpstreamCellSize"] != upCellSize {
		t.Error("UpstreamCellSize not set correctly")
	}
	if msg5.ParamsInt["NextFreeTrusteeID"] != 0 {
		t.Error("NextFreeTrusteeID not set correctly")
	}
	if msg5.ParamsStr["DCNetType"] != "Simple" {
		t.Error("DCNetType not set correctly")
	}

	//since startNow = true, trustee sends TRU_REL_TELL_PK
	trusteePub, trusteePriv := crypto.NewKeyPair()
	_ = trusteePriv
	msg6 := net.TRU_REL_TELL_PK{
		TrusteeID: 0,
		Pk:        trusteePub,
	}
	if err := relay.ReceivedMessage(msg6); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}
	if relay.stateMachine.State() != "COLLECTING_CLIENT_PKS" {
		t.Error("In wrong state ! we should be in COLLECTING_CLIENT_PKS, but are in ", relay.stateMachine.State())
	}

	// should send REL_CLI_TELL_TRUSTEES_PK to clients
	msg7, err := getClientMessage("REL_CLI_TELL_TRUSTEES_PK")
	if err != nil {
		t.Error(err)
	}
	msg8 := msg7.(*net.REL_CLI_TELL_TRUSTEES_PK)

	if !msg8.Pks[0].Equal(trusteePub) {
		t.Error("Relay sent wrong public key")
	}

	//should receive a CLI_REL_TELL_PK_AND_EPH_PK
	cliPub, cliPriv := crypto.NewKeyPair()
	cliEphPub, cliEphPriv := crypto.NewKeyPair()
	_ = cliPriv
	_ = cliEphPriv
	msg9 := net.CLI_REL_TELL_PK_AND_EPH_PK{
		ClientID: 0,
		Pk:       cliPub,
		EphPk:    cliEphPub,
	}
	if err := relay.ReceivedMessage(msg9); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}
	if relay.stateMachine.State() != "COLLECTING_SHUFFLES" {
		t.Error("In wrong state ! we should be in COLLECTING_SHUFFLES, but are in ", relay.stateMachine.State())
	}

	// should send REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE to clients
	msg10, err := getTrusteeMessage("REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE")
	if err != nil {
		t.Error(err)
	}
	msg11 := msg10.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)

	if !msg11.EphPks[0].Equal(cliEphPub) {
		t.Error("Relay sent wrong ephemeral public key")
	}

	//should receive a TRU_REL_TELL_NEW_BASE_AND_EPH_PKS
	msg12 := net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS{
		NewBase:   msg11.Base,
		NewEphPks: msg11.EphPks,
		Proof:     make([]byte, 50),
	}

	if err := relay.ReceivedMessage(msg12); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	if relay.stateMachine.State() != "COLLECTING_SHUFFLE_SIGNATURES" {
		t.Error("In wrong state ! we should be in COLLECTING_SHUFFLE_SIGNATURES, but are in ", relay.stateMachine.State())
	}

	// should send REL_TRU_TELL_TRANSCRIPT to clients
	msg13, err := getTrusteeMessage("REL_TRU_TELL_TRANSCRIPT")
	if err != nil {
		t.Error(err)
	}
	transcript := msg13.(*net.REL_TRU_TELL_TRANSCRIPT)

	// should receive a TRU_REL_SHUFFLE_SIG. This should fail with the wrong sig
	msg14 := net.TRU_REL_SHUFFLE_SIG{
		TrusteeID: 0,
		Sig:       make([]byte, 0)}
	if err := relay.ReceivedMessage(msg14); err == nil {
		t.Error("Relay should not continue if the signature is not valid !")
	}
	rs.neffShuffle.SignatureCount = 0

	//prepare the transcript signature. Since it is OK, we're gonna sign only the latest permutation
	var blob []byte

	lastSharesByte, err := transcript.Bases[0].MarshalBinary()
	if err != nil {
		t.Error("Can't marshall the last shares...")
	}
	blob = append(blob, lastSharesByte...)

	for j := 0; j < nClients; j++ {
		pkBytes, err := transcript.EphPks[0].Keys[j].MarshalBinary()
		if err != nil {
			t.Error("Can't marshall shuffled public key" + strconv.Itoa(j))
		}
		blob = append(blob, pkBytes...)
	}
	signature := crypto.SchnorrSign(config.CryptoSuite, random.Stream, blob, trusteePriv)

	msg15 := net.TRU_REL_SHUFFLE_SIG{
		TrusteeID: 0,
		Sig:       signature}
	if err := relay.ReceivedMessage(msg15); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}
	if relay.stateMachine.State() != "COMMUNICATING" {
		t.Error("In wrong state ! we should be in COMMUNICATING, but are in ", relay.stateMachine.State())
	}

	// should send REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG to clients
	msg16, err := getClientMessage("REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG")
	if err != nil {
		t.Error(err)
	}
	_ = msg16.(*net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)

	// should receive a CLI_REL_DATA_UPSTREAM
	msg17 := net.CLI_REL_UPSTREAM_DATA{
		ClientID: 0,
		RoundID:  0,
		Data:     make([]byte, upCellSize),
	}
	if err := relay.ReceivedMessage(msg17); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	//not enough to change round !
	if rs.roundManager.CurrentRound() != 0 {
		t.Error("Should still be in round 0, no data from trustee")
	}

	msg18 := net.TRU_REL_DC_CIPHER{
		TrusteeID: 0,
		RoundID:   0,
		Data:      make([]byte, upCellSize),
	}
	if err := relay.ReceivedMessage(msg18); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	//wait to trigger the timeouts
	time.Sleep(3 * time.Second)

	//suppose we receive a ALL_ALL_SHUTDOWN (since we had a timeout)
	shutdownMsg := net.ALL_ALL_SHUTDOWN{}
	if err := relay.ReceivedMessage(shutdownMsg); err != nil {
		t.Error("Should handle this ALL_ALL_SHUTDOWN message, but", err)
	}
	if relay.stateMachine.State() != "SHUTDOWN" {
		t.Error("RELAY should be in state SHUTDOWN")
	}
}

func TestRelayRun2(t *testing.T) {

	timeoutHandler := func(clients, trustees []int) { log.Error(clients, trustees) }
	resultChan := make(chan interface{}, 1)

	msgSender := new(TestMessageSender)
	msw := newTestMessageSenderWrapper(msgSender)
	sentToClient = make([]interface{}, 0)
	sentToTrustee = make([]interface{}, 0)
	dataForClients := make(chan []byte, 6)
	dataFromDCNet := make(chan []byte, 3)
	ocSleep := 1000

	relay := NewRelay(true, dataForClients, dataFromDCNet, resultChan, ocSleep, timeoutHandler, msw)
	rs := relay.relayState

	//we start by receiving a ALL_ALL_PARAMETERS from relay
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true
	nClients := 1
	nTrustees := 1
	upCellSize := 1500
	dcNetType := "Simple"
	msg.Add("StartNow", true)
	msg.Add("NClients", nClients)
	msg.Add("NTrustees", nTrustees)
	msg.Add("UpstreamCellSize", upCellSize)
	msg.Add("DownstreamCellSize", 10*upCellSize)
	msg.Add("WindowSize", 1)
	msg.Add("UseUDP", true)
	msg.Add("UseDummyDataDown", true)
	msg.Add("ExperimentRoundLimit", 2)
	msg.Add("DCNetType", dcNetType)

	if err := relay.ReceivedMessage(*msg); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send ALL_ALL_PARAMETERS to clients
	msg2, err := getClientMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	_ = msg2.(*net.ALL_ALL_PARAMETERS_NEW)

	// should send ALL_ALL_PARAMETERS to trustees
	msg4, err := getTrusteeMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	_ = msg4.(*net.ALL_ALL_PARAMETERS_NEW)

	//since startNow = true, trustee sends TRU_REL_TELL_PK
	trusteePub, trusteePriv := crypto.NewKeyPair()
	_ = trusteePriv
	msg6 := net.TRU_REL_TELL_PK{
		TrusteeID: 0,
		Pk:        trusteePub,
	}
	if err := relay.ReceivedMessage(msg6); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_CLI_TELL_TRUSTEES_PK to clients
	msg7, err := getClientMessage("REL_CLI_TELL_TRUSTEES_PK")
	if err != nil {
		t.Error(err)
	}
	_ = msg7.(*net.REL_CLI_TELL_TRUSTEES_PK)

	//should receive a CLI_REL_TELL_PK_AND_EPH_PK
	cliPub, cliPriv := crypto.NewKeyPair()
	cliEphPub, cliEphPriv := crypto.NewKeyPair()
	_ = cliPriv
	_ = cliEphPriv
	msg9 := net.CLI_REL_TELL_PK_AND_EPH_PK{
		ClientID: 0,
		Pk:       cliPub,
		EphPk:    cliEphPub,
	}
	if err := relay.ReceivedMessage(msg9); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE to clients
	msg10, err := getTrusteeMessage("REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE")
	if err != nil {
		t.Error(err)
	}
	msg11 := msg10.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)

	//should receive a TRU_REL_TELL_NEW_BASE_AND_EPH_PKS
	msg12 := net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS{
		NewBase:   msg11.Base,
		NewEphPks: msg11.EphPks,
		Proof:     make([]byte, 50),
	}
	if err := relay.ReceivedMessage(msg12); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_TRU_TELL_TRANSCRIPT to clients
	msg13, err := getTrusteeMessage("REL_TRU_TELL_TRANSCRIPT")
	if err != nil {
		t.Error(err)
	}
	transcript := msg13.(*net.REL_TRU_TELL_TRANSCRIPT)

	//prepare the transcript signature. Since it is OK, we're gonna sign only the latest permutation
	var blob []byte

	lastSharesByte, err := transcript.Bases[0].MarshalBinary()
	if err != nil {
		t.Error("Can't marshall the last shares...")
	}
	blob = append(blob, lastSharesByte...)

	for j := 0; j < nClients; j++ {
		pkBytes, err := transcript.EphPks[0].Keys[j].MarshalBinary()
		if err != nil {
			t.Error("Can't marshall shuffled public key" + strconv.Itoa(j))
		}
		blob = append(blob, pkBytes...)
	}
	signature := crypto.SchnorrSign(config.CryptoSuite, random.Stream, blob, trusteePriv)

	//should receive a TRU_REL_SHUFFLE_SIG
	msg15 := net.TRU_REL_SHUFFLE_SIG{
		TrusteeID: 0,
		Sig:       signature}
	if err := relay.ReceivedMessage(msg15); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG to clients
	msg16, err := getClientMessage("REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG")
	if err != nil {
		t.Error(err)
	}
	_ = msg16.(*net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)

	// should receive a TRU_REL_DC_CIPHER
	msg17 := net.TRU_REL_DC_CIPHER{
		TrusteeID: 0,
		RoundID:   0,
		Data:      make([]byte, upCellSize),
	}
	if err := relay.ReceivedMessage(msg17); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	//not enough to change round !
	if rs.roundManager.CurrentRound() != 0 {
		t.Error("Should still be in round 0, no data from trustee")
	}

	msg18 := net.CLI_REL_UPSTREAM_DATA{
		ClientID: 0,
		RoundID:  0,
		Data:     make([]byte, upCellSize),
	}
	if err := relay.ReceivedMessage(msg18); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should receive a TRU_REL_DATA_UPSTREAM
	msg19 := net.TRU_REL_DC_CIPHER{
		TrusteeID: 0,
		RoundID:   1,
		Data:      make([]byte, upCellSize),
	}
	if err := relay.ReceivedMessage(msg19); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	//this time the client message finishes the round
	msg20 := net.CLI_REL_UPSTREAM_DATA{
		ClientID: 0,
		RoundID:  1,
		Data:     make([]byte, upCellSize),
	}
	if err := relay.ReceivedMessage(msg20); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	//suppose we should refuse this random message
	randomMsg := net.REL_CLI_TELL_TRUSTEES_PK{}
	if err := relay.ReceivedMessage(randomMsg); err == nil {
		t.Error("Should not accept this REL_CLI_TELL_TRUSTEES_PK message")
	}
}

func TestRelayRun3(t *testing.T) {

	timeoutHandler := func(clients, trustees []int) { log.Error(clients, trustees) }
	resultChan := make(chan interface{}, 1)

	msgSender := new(TestMessageSender)
	msw := newTestMessageSenderWrapper(msgSender)
	sentToClient = make([]interface{}, 0)
	sentToTrustee = make([]interface{}, 0)
	dataForClients := make(chan []byte, 6)
	dataFromDCNet := make(chan []byte, 3)
	ocSleep := 1000

	relay := NewRelay(true, dataForClients, dataFromDCNet, resultChan, ocSleep, timeoutHandler, msw)

	//we start by receiving a ALL_ALL_PARAMETERS from relay
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true
	nClients := 1
	nTrustees := 2
	upCellSize := 1500
	dcNetType := "Simple"
	msg.Add("StartNow", true)
	msg.Add("NClients", nClients)
	msg.Add("NTrustees", nTrustees)
	msg.Add("UpstreamCellSize", upCellSize)
	msg.Add("DownstreamCellSize", 10*upCellSize)
	msg.Add("WindowSize", 1)
	msg.Add("UseUDP", false)
	msg.Add("UseDummyDataDown", false)
	msg.Add("ExperimentRoundLimit", -1)
	msg.Add("DCNetType", dcNetType)

	if err := relay.ReceivedMessage(*msg); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send ALL_ALL_PARAMETERS to clients
	msg2, err := getClientMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	_ = msg2.(*net.ALL_ALL_PARAMETERS_NEW)

	// should send ALL_ALL_PARAMETERS to trustees
	msg4, err := getTrusteeMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	_ = msg4.(*net.ALL_ALL_PARAMETERS_NEW)
	msg4, err = getTrusteeMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	_ = msg4.(*net.ALL_ALL_PARAMETERS_NEW)

	//since startNow = true, trustee sends TRU_REL_TELL_PK
	trusteePub, trusteePriv := crypto.NewKeyPair()
	_ = trusteePriv
	msg6 := net.TRU_REL_TELL_PK{
		TrusteeID: 0,
		Pk:        trusteePub,
	}
	if err := relay.ReceivedMessage(msg6); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}
	msg6_2 := net.TRU_REL_TELL_PK{
		TrusteeID: 1,
		Pk:        trusteePub,
	}
	if err := relay.ReceivedMessage(msg6_2); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_CLI_TELL_TRUSTEES_PK to clients
	msg7, err := getClientMessage("REL_CLI_TELL_TRUSTEES_PK")
	if err != nil {
		t.Error(err)
	}
	_ = msg7.(*net.REL_CLI_TELL_TRUSTEES_PK)

	//should receive a CLI_REL_TELL_PK_AND_EPH_PK
	cliPub, cliPriv := crypto.NewKeyPair()
	cliEphPub, cliEphPriv := crypto.NewKeyPair()
	_ = cliPriv
	_ = cliEphPriv
	msg9 := net.CLI_REL_TELL_PK_AND_EPH_PK{
		ClientID: 0,
		Pk:       cliPub,
		EphPk:    cliEphPub,
	}
	if err := relay.ReceivedMessage(msg9); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE to clients
	msg10, err := getTrusteeMessage("REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE")
	if err != nil {
		t.Error(err)
	}
	msg11 := msg10.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)

	//should receive a TRU_REL_TELL_NEW_BASE_AND_EPH_PKS
	msg12 := net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS{
		NewBase:   msg11.Base,
		NewEphPks: msg11.EphPks,
		Proof:     make([]byte, 50),
	}
	if err := relay.ReceivedMessage(msg12); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE to clients
	msg10_2, err := getTrusteeMessage("REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE")
	if err != nil {
		t.Error(err)
	}
	_ = msg10_2.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)

	//should receive a TRU_REL_TELL_NEW_BASE_AND_EPH_PKS
	msg12_2 := net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS{
		NewBase:   msg11.Base,
		NewEphPks: msg11.EphPks,
		Proof:     make([]byte, 50),
	}
	if err := relay.ReceivedMessage(msg12_2); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_TRU_TELL_TRANSCRIPT to trustees
	msg13, err := getTrusteeMessage("REL_TRU_TELL_TRANSCRIPT")
	if err != nil {
		t.Error(err)
	}
	transcript := msg13.(*net.REL_TRU_TELL_TRANSCRIPT)

	//prepare the transcript signature. Since it is OK, we're gonna sign only the latest permutation
	var blob []byte

	lastSharesByte, err := transcript.Bases[0].MarshalBinary()
	if err != nil {
		t.Error("Can't marshall the last shares...")
	}
	blob = append(blob, lastSharesByte...)

	for j := 0; j < nClients; j++ {
		pkBytes, err := transcript.EphPks[0].Keys[j].MarshalBinary()
		if err != nil {
			t.Error("Can't marshall shuffled public key" + strconv.Itoa(j))
		}
		blob = append(blob, pkBytes...)
	}
	signature := crypto.SchnorrSign(config.CryptoSuite, random.Stream, blob, trusteePriv)

	//should receive two TRU_REL_SHUFFLE_SIG
	msg15 := net.TRU_REL_SHUFFLE_SIG{
		TrusteeID: 0,
		Sig:       signature}
	if err := relay.ReceivedMessage(msg15); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}
	msg15 = net.TRU_REL_SHUFFLE_SIG{
		TrusteeID: 1,
		Sig:       signature}
	if err := relay.ReceivedMessage(msg15); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	// should send REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG to clients
	msg16, err := getClientMessage("REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG")
	if err != nil {
		t.Error(err)
	}
	_ = msg16.(*net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)

	// should receive a TRU_REL_DC_CIPHER
	msg17 := net.TRU_REL_DC_CIPHER{
		TrusteeID: 0,
		RoundID:   0,
		Data:      make([]byte, upCellSize),
	}

	if err := relay.ReceivedMessage(msg17); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}
	msg17 = net.TRU_REL_DC_CIPHER{
		TrusteeID: 1,
		RoundID:   0,
		Data:      make([]byte, upCellSize),
	}
	if err := relay.ReceivedMessage(msg17); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}
	// should receive a CLI_REL_UPSTREAM_DATA
	currentTime := client.MsTimeStampNow()
	latencyMessage := []byte{170, 170, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(latencyMessage[4:12], uint64(currentTime))
	msg18 := net.CLI_REL_UPSTREAM_DATA{
		ClientID: 0,
		RoundID:  0,
		Data:     latencyMessage,
	}
	//error here !
	if err := relay.ReceivedMessage(msg18); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	//should send a downstream data

	// should send REL_CLI_DOWNSTREAM_DATA to clients
	msg19, err := getClientMessage("REL_CLI_DOWNSTREAM_DATA")
	if err != nil {
		t.Error(err)
	}
	msg20 := msg19.(*net.REL_CLI_DOWNSTREAM_DATA)
	if !bytes.Equal(msg20.Data[0:12], latencyMessage) {
		t.Error("Relay should re-send latency messages")
	}

	msg21 := net.CLI_REL_UPSTREAM_DATA{
		ClientID: 1,
		RoundID:  0,
		Data:     nil,
	}
	if err := relay.Received_CLI_REL_UPSTREAM_DATA(msg21); err != nil {
		t.Error("Relay should be able to receive this message but", err)
	}

}

func TestRelayRun4(t *testing.T) {

	timeoutHandler := func(clients, trustees []int) { log.Error(clients, trustees) }
	resultChan := make(chan interface{}, 1)

	msgSender := new(TestMessageSender)
	msw := newTestMessageSenderWrapper(msgSender)
	sentToClient = make([]interface{}, 0)
	sentToTrustee = make([]interface{}, 0)
	dataForClients := make(chan []byte, 6)
	dataFromDCNet := make(chan []byte, 3)
	ocSleep := 1000

	relay := NewRelay(true, dataForClients, dataFromDCNet, resultChan, ocSleep, timeoutHandler, msw)

	//we start by receiving a ALL_ALL_PARAMETERS from relay
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true
	nClients := 1
	nTrustees := 2
	upCellSize := 1500
	dcNetType := "Verifiable"
	msg.Add("StartNow", true)
	msg.Add("NClients", nClients)
	msg.Add("NTrustees", nTrustees)
	msg.Add("UpstreamCellSize", upCellSize)
	msg.Add("DownstreamCellSize", 10*upCellSize)
	msg.Add("WindowSize", 1)
	msg.Add("UseUDP", false)
	msg.Add("UseDummyDataDown", false)
	msg.Add("ExperimentRoundLimit", -1)
	msg.Add("DCNetType", dcNetType)

	if err := relay.ReceivedMessage(*msg); err != nil {
		t.Error("Relay should be able to receive this message, but", err)
	}

	if relay.relayState.dcNetType != "Verifiable" {
		t.Error("DCNetType not set correctly")
	}

	// should send ALL_ALL_PARAMETERS to clients
	msg2, err := getClientMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	msg3 := msg2.(*net.ALL_ALL_PARAMETERS_NEW)

	if msg3.ParamsStr["DCNetType"] != "Verifiable" {
		t.Error("DCNetType not passed correctly to Client")
	}

	// should send ALL_ALL_PARAMETERS to trustees
	msg4, err := getTrusteeMessage("ALL_ALL_PARAMETERS")
	if err != nil {
		t.Error(err)
	}
	msg5 := msg4.(*net.ALL_ALL_PARAMETERS_NEW)

	if msg5.ParamsStr["DCNetType"] != "Verifiable" {
		t.Error("DCNetType not passed correctly to Trustee")
	}

	relay2 := NewRelay(true, dataForClients, dataFromDCNet, resultChan, ocSleep, timeoutHandler, msw)

	//we start by receiving a ALL_ALL_PARAMETERS from relay
	msg21 := new(net.ALL_ALL_PARAMETERS_NEW)
	msg21.ForceParams = true
	dcNetType2 := "Random"
	msg21.Add("StartNow", true)
	msg21.Add("NClients", nClients)
	msg21.Add("NTrustees", nTrustees)
	msg21.Add("UpstreamCellSize", upCellSize)
	msg21.Add("DownstreamCellSize", 10*upCellSize)
	msg21.Add("WindowSize", 1)
	msg21.Add("UseUDP", false)
	msg21.Add("UseDummyDataDown", false)
	msg21.Add("ExperimentRoundLimit", -1)
	msg21.Add("DCNetType", dcNetType2)

	if err := relay2.ReceivedMessage(*msg21); err == nil {
		t.Error("Relay should output an error when DCNetType != {Simple, Verifiable}")
	}
}
