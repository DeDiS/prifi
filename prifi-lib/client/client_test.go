package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/crypto"
	prifilog "github.com/lbarman/prifi/prifi-lib/log"
	"github.com/lbarman/prifi/prifi-lib/net"
	"github.com/lbarman/prifi/prifi-lib/scheduler"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
	"testing"
	"time"
)

/**
 * Message Sender
 */
type TestMessageSender struct {
}

func (t *TestMessageSender) SendToClient(i int, msg interface{}) error {
	return errors.New("Clients should never sent to other clients")
}
func (t *TestMessageSender) SendToTrustee(i int, msg interface{}) error {
	return errors.New("Clients should never sent to other trustees")
}

var sentToRelay []interface{}

func (t *TestMessageSender) SendToRelay(msg interface{}) error {
	sentToRelay = append(sentToRelay, msg)
	return nil
}
func (t *TestMessageSender) BroadcastToAllClients(msg interface{}) error {
	return errors.New("Clients should never sent to other clients")
}
func (t *TestMessageSender) ClientSubscribeToBroadcast(clientID int, messageReceived func(interface{}) error, startStopChan chan bool) error {
	return nil
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

func TestClient(t *testing.T) {

	msgSender := new(TestMessageSender)
	msw := newTestMessageSenderWrapper(msgSender)
	sentToRelay = make([]interface{}, 0)
	in := make(chan []byte, 6)
	out := make(chan []byte, 3)

	client := NewClient(true, true, in, out, msw)

	//when receiving no message, client should have some parameters ready
	cs := client.clientState
	if cs.DataOutputEnabled != true {
		t.Error("DataOutputEnabled was not set correctly")
	}
	if client.stateMachine.State() != "BEFORE_INIT" {
		t.Error("State was not set correctly")
	}
	if cs.privateKey == nil || cs.PublicKey == nil {
		t.Error("Private/Public key not set")
	}
	if cs.timeStatistics == nil {
		t.Error("Statistics should have been set")
	}
	if cs.StartStopReceiveBroadcast != nil {
		t.Error("StartStopReceiveBroadcast should *not* have been set")
	}

	//we start by receiving a ALL_ALL_PARAMETERS from relay
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true
	clientID := 3
	nTrustees := 2
	upCellSize := 1500
	dcNetType := "Simple"
	msg.Add("NClients", 3)
	msg.Add("NTrustees", nTrustees)
	msg.Add("UpstreamCellSize", upCellSize)
	msg.Add("NextFreeClientID", clientID)
	msg.Add("UseUDP", true)
	msg.Add("DCNetType", dcNetType)

	if err := client.ReceivedMessage(*msg); err != nil {
		t.Error("Client should be able to receive this message:", err)
	}

	if cs.nClients != 3 {
		t.Error("NClients should be 3")
	}
	if cs.nTrustees != nTrustees {
		t.Error("nTrustees should be 2")
	}
	if cs.PayloadLength != 1500 {
		t.Error("PayloadLength should be 1500")
	}
	if cs.ID != clientID {
		t.Error("ID should be 3")
	}
	if cs.RoundNo != 0 {
		t.Error("RoundNumber should be 0")
	}
	if cs.StartStopReceiveBroadcast == nil {
		t.Error("StartStopReceiveBroadcast should now have been set")
	}
	if cs.UseUDP != true {
		t.Error("UseUDP should now have been set to true")
	}
	if cs.DCNet_RoundManager == nil {
		t.Error("DCNet_RoundManager should have been created")
	}
	if len(cs.TrusteePublicKey) != nTrustees {
		t.Error("Len(TrusteePKs) should be equal to NTrustees")
	}
	if len(cs.sharedSecrets) != nTrustees {
		t.Error("Len(SharedSecrets) should be equal to NTrustees")
	}
	if client.stateMachine.State() != "INITIALIZING" {
		t.Error("Client should be in state CLIENT_STATE_INITIALIZING")
	}

	//Should receive a Received_REL_CLI_TELL_TRUSTEES_PK
	trusteesPubKeys := make([]abstract.Point, nTrustees)
	trusteesPrivKeys := make([]abstract.Scalar, nTrustees)
	for i := 0; i < nTrustees; i++ {
		trusteesPubKeys[i], trusteesPrivKeys[i] = crypto.NewKeyPair()
	}
	msg2 := net.REL_CLI_TELL_TRUSTEES_PK{Pks: trusteesPubKeys}
	if err := client.ReceivedMessage(msg2); err != nil {
		t.Error("Should be able to receive this message,", err.Error())
	}

	for i := 0; i < nTrustees; i++ {
		if !cs.TrusteePublicKey[i].Equal(trusteesPubKeys[i]) {
			t.Error("Pub key", i, "has not been stored correctly")
		}
		myPrivKey := cs.privateKey
		if !cs.sharedSecrets[i].Equal(config.CryptoSuite.Point().Mul(trusteesPubKeys[i], myPrivKey)) {
			t.Error("Shared secret", i, "has not been computed correctly")
		}
	}

	if cs.EphemeralPublicKey == nil {
		t.Error("Ephemeral pub key shouldn't be nil")
	}
	if cs.ephemeralPrivateKey == nil {
		t.Error("Ephemeral priv key shouldn't be nil")
	}
	if client.stateMachine.State() != "EPH_KEYS_SENT" {
		t.Error("Client should be in state CLIENT_STATE_INITIALIZING")
	}

	//Should send a CLI_REL_TELL_PK_AND_EPH_PK
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_TELL_PK_AND_EPH_PK to the relay")
	}
	msg3 := sentToRelay[0].(*net.CLI_REL_TELL_PK_AND_EPH_PK)
	sentToRelay = make([]interface{}, 0)
	if msg3.ClientID != clientID {
		t.Error("Client sent a wrong client ID")
	}
	if !msg3.EphPk.Equal(cs.EphemeralPublicKey) {
		t.Error("Client did not send his ephemeral public key")
	}
	if !msg3.Pk.Equal(cs.PublicKey) {
		t.Error("Client did not send his ephemeral public key")
	}

	//neff shuffle
	n := new(scheduler.NeffShuffle)
	n.Init()
	n.RelayView.Init(nTrustees)
	trustees := make([]*scheduler.NeffShuffle, nTrustees)
	for i := 0; i < nTrustees; i++ {
		trustees[i] = new(scheduler.NeffShuffle)
		trustees[i].Init()
		trustees[i].TrusteeView.Init(i, trusteesPrivKeys[i], trusteesPubKeys[i])
	}
	n.RelayView.AddClient(cs.EphemeralPublicKey)
	isDone := false
	i := 0
	for !isDone {
		toSend, _, _ := n.RelayView.SendToNextTrustee()
		parsed := toSend.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)
		toSend2, _ := trustees[i].TrusteeView.ReceivedShuffleFromRelay(parsed.Base, parsed.EphPks, false, make([]byte, 1))
		parsed2 := toSend2.(*net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS)
		isDone, _ = n.RelayView.ReceivedShuffleFromTrustee(parsed2.NewBase, parsed2.NewEphPks, parsed2.Proof)
		i++
	}
	toSend3, _ := n.RelayView.SendTranscript()
	parsed3 := toSend3.(*net.REL_TRU_TELL_TRANSCRIPT)
	for j := 0; j < nTrustees; j++ {
		toSend4, _ := trustees[j].TrusteeView.ReceivedTranscriptFromRelay(parsed3.Bases, parsed3.GetKeys(), parsed3.GetProofs())
		parsed4 := toSend4.(*net.TRU_REL_SHUFFLE_SIG)
		n.RelayView.ReceivedSignatureFromTrustee(parsed4.TrusteeID, parsed4.Sig)
	}
	toSend5, _ := n.RelayView.VerifySigsAndSendToClients(trusteesPubKeys)
	parsed5 := toSend5.(*net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)

	//should receive a Received_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG
	err4 := client.ReceivedMessage(*parsed5)
	if err4 != nil {
		t.Error("Should be able to receive this message,", err4)
	}

	if cs.MySlot != 0 {
		t.Error("should have a slot", cs.MySlot)
	}
	if cs.BufferedRoundData == nil {
		t.Error("should have instanciated BufferedRoundData")
	}

	//Should send a CLI_REL_UPSTREAM_DATA
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_UPSTREAM_DATA to the relay")
	}
	msg6 := sentToRelay[0].(*net.CLI_REL_UPSTREAM_DATA)
	sentToRelay = make([]interface{}, 0)
	if msg6.ClientID != clientID {
		t.Error("Client sent a wrong ID")
	}
	if msg6.RoundID != int32(0) {
		t.Error("Client sent a wrong RoundID")
	}
	if len(msg6.Data) != upCellSize {
		t.Error("Client sent a payload with a wrong size")
	}
	if cs.RoundNo != int32(1) {
		t.Error("should be in round 1, we sent a CLI_REL_UPSTREAM_DATA (there is no REL_CLI_DOWNSTREAM_DATA on round 0)")
	}

	//the client has this to send (from the DC-net)
	dataUp1 := []byte{4, 5, 6}
	in <- dataUp1

	//Receive some data down
	dataDown := []byte{1, 2, 3}
	msg7 := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:    1,
		Data:       dataDown,
		FlagResync: false,
	}
	err := client.ReceivedMessage(msg7)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}
	data2 := <-out
	if !bytes.Equal(dataDown, data2) {
		t.Error("Client should push the received data to the out channel")
	}

	//Should send a CLI_REL_UPSTREAM_DATA
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_UPSTREAM_DATA to the relay")
	}
	msg8 := sentToRelay[0].(*net.CLI_REL_UPSTREAM_DATA)
	sentToRelay = make([]interface{}, 0)
	if msg8.ClientID != clientID {
		t.Error("Client sent a wrong ID")
	}
	if msg8.RoundID != int32(1) {
		t.Error("Client sent a wrong RoundID")
	}
	if len(msg8.Data) != upCellSize {
		t.Error("Client sent a payload with a wrong size")
	}
	if cs.RoundNo != int32(2) {
		t.Error("should be in round 2")
	}

	cs.nClients = 2 //so 1/2 rounds are ours.

	//Receive some (obsolete) data down
	dataDown = []byte{10, 11, 12}
	msg9_ignored := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:    -1,
		Data:       dataDown,
		FlagResync: true, //this should not matter
	}
	err = client.ReceivedMessage(msg9_ignored)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}
	if cs.RoundNo != int32(2) {
		t.Error("should still be in round 2")
	}
	if len(sentToRelay) > 0 {
		t.Error("should not have sent anything")
	}

	//Receive some (future) data down
	dataDown = []byte{90, 91, 92}
	msg9_futur := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:    3,
		Data:       dataDown,
		FlagResync: false,
	}
	err = client.ReceivedMessage(msg9_futur)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}
	if cs.RoundNo != int32(4) {
		t.Error("should now be in round 4", cs.RoundNo)
	}
	if len(sentToRelay) != 1 {
		t.Error("should have sent one message")
	}
	sentToRelay = make([]interface{}, 0)
	_ = <-out

	//Receive some data down
	dataDown = []byte{10, 11, 12}
	msg9 := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:    4,
		Data:       dataDown,
		FlagResync: false,
	}
	msg9udp := net.REL_CLI_DOWNSTREAM_DATA_UDP{
		REL_CLI_DOWNSTREAM_DATA: msg9,
	}
	err = client.ReceivedMessage(msg9udp)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}
	data3 := <-out
	if !bytes.Equal(dataDown, data3) {
		t.Error("Client should push the received data to the out channel")
	}

	//Should send a CLI_REL_UPSTREAM_DATA
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_UPSTREAM_DATA to the relay")
	}
	msg10 := sentToRelay[0].(*net.CLI_REL_UPSTREAM_DATA)
	sentToRelay = sentToRelay[1:]
	if msg10.ClientID != clientID {
		t.Error("Client sent a wrong ID")
	}
	if msg10.RoundID != int32(4) {
		t.Error("Client sent a wrong RoundID")
	}
	if len(msg10.Data) != upCellSize {
		t.Error("Client sent a payload with a wrong size")
	}
	if cs.RoundNo != int32(5) { //we did round 3 already
		t.Error("should be in round 5, not ", cs.RoundNo)
	}

	//Receive some data down, with nothing to say, and latencytest=true
	cs.LatencyTest = &prifilog.LatencyTests{
		DoLatencyTests:       true,
		LatencyTestsInterval: time.Second * 0,
		NextLatencyTest:      time.Now(),
	}
	dataDown = []byte{100, 101, 102}

	currentTime := MsTimeStampNow()
	latencyMessage := []byte{170, 170, 0, 1, 0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(latencyMessage[4:12], uint64(currentTime))
	msg12 := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:    5,
		Data:       latencyMessage,
		FlagResync: false,
	}
	err = client.ReceivedMessage(msg12)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}
	if cs.RoundNo != int32(6) {
		t.Error("should still be in round 6, not", cs.RoundNo)
	}

	//Should send a CLI_REL_UPSTREAM_DATA with latency test
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_UPSTREAM_DATA to the relay")
	}
	latencyMsg := sentToRelay[0].(*net.CLI_REL_UPSTREAM_DATA)
	sentToRelay = make([]interface{}, 0)
	if latencyMsg.ClientID != clientID {
		t.Error("Client sent a wrong ID")
	}
	if latencyMsg.RoundID != int32(5) {
		t.Error("Client sent a wrong RoundID")
	}
	if len(latencyMsg.Data) != upCellSize {
		t.Error("Client sent a payload with a wrong size")
	}

	//Receive some data down with FlagResync = true
	dataDown = []byte{100, 101, 102}
	msg13 := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:    6,
		Data:       dataDown,
		FlagResync: true, //should stop the client
	}
	err = client.ReceivedMessage(msg13)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}
	if cs.RoundNo != int32(6) {
		t.Error("should still be in round 6", cs.RoundNo)
	}
	if len(sentToRelay) > 0 {
		t.Error("should not have sent anything")
	}
	if client.stateMachine.State() != "INITIALIZING" {
		t.Error("Should be in state CLIENT_STATE_INITIALIZING", client.stateMachine.State())
	}

	randomMsg := &net.CLI_REL_TELL_PK_AND_EPH_PK{}
	if err := client.ReceivedMessage(randomMsg); err == nil {
		t.Error("Should not accept this CLI_REL_TELL_PK_AND_EPH_PK message")
	}

	//if we send a shutdown
	shutdownMsg := net.ALL_ALL_SHUTDOWN{}
	client.ReceivedMessage(shutdownMsg)
	if client.stateMachine.State() != "SHUTDOWN" {
		t.Error("Should be in SHUTDOWN state after receiving this message")
	}

	//t.SkipNow() //we started a goroutine, let's kill everything, we're good
}

func TestClient2(t *testing.T) {

	msgSender := new(TestMessageSender)
	msw := newTestMessageSenderWrapper(msgSender)
	sentToRelay = make([]interface{}, 0)
	in := make(chan []byte, 6)
	out := make(chan []byte, 3)

	client := NewClient(true, true, in, out, msw)
	cs := client.clientState

	//we start by receiving a ALL_ALL_PARAMETERS from relay
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true
	clientID := 3
	nTrustees := 2
	upCellSize := 1500
	dcNetType := "Simple"
	msg.Add("NClients", 1)
	msg.Add("NTrustees", nTrustees)
	msg.Add("UpstreamCellSize", upCellSize)
	msg.Add("NextFreeClientID", clientID)
	msg.Add("UseUDP", true)
	msg.Add("DCNetType", dcNetType)

	if err := client.ReceivedMessage(*msg); err != nil {
		t.Error("Client should be able to receive this message:", err)
	}

	//Should receive a Received_REL_CLI_TELL_TRUSTEES_PK
	trusteesPubKeys := make([]abstract.Point, nTrustees)
	trusteesPrivKeys := make([]abstract.Scalar, nTrustees)
	for i := 0; i < nTrustees; i++ {
		trusteesPubKeys[i], trusteesPrivKeys[i] = crypto.NewKeyPair()
	}
	msg2 := net.REL_CLI_TELL_TRUSTEES_PK{Pks: trusteesPubKeys}
	if err := client.ReceivedMessage(msg2); err != nil {
		t.Error("Should be able to receive this message,", err.Error())
	}

	//Should send a CLI_REL_TELL_PK_AND_EPH_PK
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_TELL_PK_AND_EPH_PK to the relay")
	}
	_ = sentToRelay[0].(*net.CLI_REL_TELL_PK_AND_EPH_PK)
	sentToRelay = make([]interface{}, 0)

	//neff shuffle
	n := new(scheduler.NeffShuffle)
	n.Init()
	n.RelayView.Init(nTrustees)
	trustees := make([]*scheduler.NeffShuffle, nTrustees)
	for i := 0; i < nTrustees; i++ {
		trustees[i] = new(scheduler.NeffShuffle)
		trustees[i].Init()
		trustees[i].TrusteeView.Init(i, trusteesPrivKeys[i], trusteesPubKeys[i])
	}
	n.RelayView.AddClient(cs.EphemeralPublicKey)
	isDone := false
	i := 0
	for !isDone {
		toSend, _, _ := n.RelayView.SendToNextTrustee()
		parsed := toSend.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)
		toSend2, _ := trustees[i].TrusteeView.ReceivedShuffleFromRelay(parsed.Base, parsed.EphPks, false, make([]byte, 1))
		parsed2 := toSend2.(*net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS)
		isDone, _ = n.RelayView.ReceivedShuffleFromTrustee(parsed2.NewBase, parsed2.NewEphPks, parsed2.Proof)
		i++
	}
	toSend3, _ := n.RelayView.SendTranscript()
	parsed3 := toSend3.(*net.REL_TRU_TELL_TRANSCRIPT)
	for j := 0; j < nTrustees; j++ {
		toSend4, _ := trustees[j].TrusteeView.ReceivedTranscriptFromRelay(parsed3.Bases, parsed3.GetKeys(), parsed3.GetProofs())
		parsed4 := toSend4.(*net.TRU_REL_SHUFFLE_SIG)
		n.RelayView.ReceivedSignatureFromTrustee(parsed4.TrusteeID, parsed4.Sig)
	}
	toSend5, _ := n.RelayView.VerifySigsAndSendToClients(trusteesPubKeys)
	parsed5 := toSend5.(*net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)

	//should receive a Received_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG
	err4 := client.ReceivedMessage(*parsed5)
	if err4 != nil {
		t.Error("Should be able to receive this message,", err4)
	}

	//Should send a CLI_REL_UPSTREAM_DATA
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_UPSTREAM_DATA to the relay")
	}
	msg6 := sentToRelay[0].(*net.CLI_REL_UPSTREAM_DATA)
	sentToRelay = make([]interface{}, 0)
	if msg6.ClientID != clientID {
		t.Error("Client sent a wrong ID")
	}
	if msg6.RoundID != int32(0) {
		t.Error("Client sent a wrong RoundID")
	}
	if len(msg6.Data) != upCellSize {
		t.Error("Client sent a payload with a wrong size")
	}
	if cs.RoundNo != int32(1) {
		t.Error("should be in round 1, we sent a CLI_REL_UPSTREAM_DATA (there is no REL_CLI_DOWNSTREAM_DATA on round 0)")
	}

	//Receive some data down (with nothing to send, should trigger a latency message)
	dataDown := []byte{1, 2, 3}
	msg7 := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:               1,
		Data:                  dataDown,
		FlagResync:            false,
		FlagOpenClosedRequest: false,
	}
	err := client.ReceivedMessage(msg7)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}
	data2 := <-out
	if !bytes.Equal(dataDown, data2) {
		t.Error("Client should push the received data to the out channel")
	}

	//Receive some data down with OpenClosedRequest=true
	msg8 := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:               2,
		Data:                  dataDown,
		FlagResync:            false,
		FlagOpenClosedRequest: true,
	}
	err = client.ReceivedMessage(msg8)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}

	//t.SkipNow() //we started a goroutine, let's kill everything, we're good
}

func TestClient3(t *testing.T) {

	msgSender := new(TestMessageSender)
	msw := newTestMessageSenderWrapper(msgSender)
	sentToRelay = make([]interface{}, 0)
	in := make(chan []byte, 6)
	out := make(chan []byte, 3)

	client := NewClient(true, true, in, out, msw)
	cs := client.clientState

	//we start by receiving a ALL_ALL_PARAMETERS from relay
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true
	clientID := 3
	nTrustees := 2
	upCellSize := 1500
	dcNetType := "Simple"
	msg.Add("NClients", 1)
	msg.Add("NTrustees", nTrustees)
	msg.Add("UpstreamCellSize", upCellSize)
	msg.Add("NextFreeClientID", clientID)
	msg.Add("UseUDP", true)
	msg.Add("DCNetType", dcNetType)

	if err := client.ReceivedMessage(*msg); err != nil {
		t.Error("Client should be able to receive this message:", err)
	}

	//Should receive a Received_REL_CLI_TELL_TRUSTEES_PK
	trusteesPubKeys := make([]abstract.Point, nTrustees)
	trusteesPrivKeys := make([]abstract.Scalar, nTrustees)
	for i := 0; i < nTrustees; i++ {
		trusteesPubKeys[i], trusteesPrivKeys[i] = crypto.NewKeyPair()
	}
	msg2 := net.REL_CLI_TELL_TRUSTEES_PK{Pks: trusteesPubKeys}
	if err := client.ReceivedMessage(msg2); err != nil {
		t.Error("Should be able to receive this message,", err.Error())
	}

	//Should send a CLI_REL_TELL_PK_AND_EPH_PK
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_TELL_PK_AND_EPH_PK to the relay")
	}
	_ = sentToRelay[0].(*net.CLI_REL_TELL_PK_AND_EPH_PK)
	sentToRelay = make([]interface{}, 0)

	//neff shuffle
	n := new(scheduler.NeffShuffle)
	n.Init()
	n.RelayView.Init(nTrustees)
	trustees := make([]*scheduler.NeffShuffle, nTrustees)
	for i := 0; i < nTrustees; i++ {
		trustees[i] = new(scheduler.NeffShuffle)
		trustees[i].Init()
		trustees[i].TrusteeView.Init(i, trusteesPrivKeys[i], trusteesPubKeys[i])
	}
	n.RelayView.AddClient(cs.EphemeralPublicKey)
	isDone := false
	i := 0
	for !isDone {
		toSend, _, _ := n.RelayView.SendToNextTrustee()
		parsed := toSend.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)
		toSend2, _ := trustees[i].TrusteeView.ReceivedShuffleFromRelay(parsed.Base, parsed.EphPks, false, make([]byte, 1))
		parsed2 := toSend2.(*net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS)
		isDone, _ = n.RelayView.ReceivedShuffleFromTrustee(parsed2.NewBase, parsed2.NewEphPks, parsed2.Proof)
		i++
	}
	toSend3, _ := n.RelayView.SendTranscript()
	parsed3 := toSend3.(*net.REL_TRU_TELL_TRANSCRIPT)
	for j := 0; j < nTrustees; j++ {
		toSend4, _ := trustees[j].TrusteeView.ReceivedTranscriptFromRelay(parsed3.Bases, parsed3.GetKeys(), parsed3.GetProofs())
		parsed4 := toSend4.(*net.TRU_REL_SHUFFLE_SIG)
		n.RelayView.ReceivedSignatureFromTrustee(parsed4.TrusteeID, parsed4.Sig)
	}
	toSend5, _ := n.RelayView.VerifySigsAndSendToClients(trusteesPubKeys)
	parsed5 := toSend5.(*net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)

	//should receive a Received_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG
	err4 := client.ReceivedMessage(*parsed5)
	if err4 != nil {
		t.Error("Should be able to receive this message,", err4)
	}

	dataUp1 := []byte{4, 5, 6}
	in <- dataUp1

	//Should send a CLI_REL_UPSTREAM_DATA
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_UPSTREAM_DATA to the relay")
	}
	msg6 := sentToRelay[0].(*net.CLI_REL_UPSTREAM_DATA)
	sentToRelay = make([]interface{}, 0)
	if msg6.ClientID != clientID {
		t.Error("Client sent a wrong ID")
	}
	if msg6.RoundID != int32(0) {
		t.Error("Client sent a wrong RoundID")
	}
	if len(msg6.Data) != upCellSize {
		t.Error("Client sent a payload with a wrong size")
	}
	if cs.RoundNo != int32(1) {
		t.Error("should be in round 1, we sent a CLI_REL_UPSTREAM_DATA (there is no REL_CLI_DOWNSTREAM_DATA on round 0)")
	}

	data := sha256.Sum256([]byte{4, 5, 7})
	hash := make([]byte, 32)
	copy(hash[:], data[:])

	//Receive some data down
	dataDown := []byte{1, 2, 3}
	msg7 := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:     1,
		Data:        dataDown,
		FlagResync:  false,
		HashRoundID: 1,
		Hash:        hash,
	}
	err := client.ReceivedMessage(msg7)
	if err != nil {
		t.Error("Client should be able to receive this data")
	}
	data2 := <-out
	if !bytes.Equal(dataDown, data2) {
		t.Error("Client should push the received data to the out channel")
	}

	//Should send a CLI_REL_UPSTREAM_DATA
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_UPSTREAM_DATA to the relay")
	}

	msg8 := sentToRelay[0].(*net.CLI_REL_UPSTREAM_DATA)
	sentToRelay = make([]interface{}, 0)
	if msg8.ClientID != clientID {
		t.Error("Client sent a wrong ID")
	}
	if msg8.RoundID != int32(1) {
		t.Error("Client sent a wrong RoundID")
	}
	if len(msg8.Data) != upCellSize {
		t.Error("Client sent a payload with a wrong size")
	}
	if cs.RoundNo != int32(2) {
		t.Error("should be in round 2")
	}

	msg9 := net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:     2,
		Data:        dataDown,
		FlagResync:  false,
		HashRoundID: 1,
		Hash:        hash,
	}
	err9 := client.ReceivedMessage(msg9)
	if err9 != nil {
		t.Error("Client should be able to receive this data")
	}

	//Should send a CLI_REL_UPSTREAM_DATA and CLI_REL_QUERY
	if len(sentToRelay) != 2 {
		t.Error("Client should have sent a CLI_REL_UPSTREAM_DATA and CLI_REL_QUERY to the relay")
	}

	msg10 := sentToRelay[0].(*net.CLI_REL_QUERY)
	if msg10.RoundID != 1 {
		t.Error("Client should have sent a QUERY for round 1")
	}

	msg10b := sentToRelay[1].(*net.CLI_REL_UPSTREAM_DATA)
	sentToRelay = make([]interface{}, 0)
	if msg10b.RoundID != int32(2) {
		t.Error("Client sent a wrong RoundID")
	}

	encryptedMessage, _ := config.CryptoSuite.Point().Pick([]byte{4, 5, 7}, config.CryptoSuite.Cipher([]byte("encryption")))
	encryptedMessage.Add(encryptedMessage, msg10.Pk)

	msg11 := net.REL_CLI_QUERY{
		RoundID:       msg10.RoundID,
		EncryptedData: encryptedMessage}

	err11 := client.ReceivedMessage(msg11)
	if err11 != nil {
		t.Error("Client should be able to receive this data")
	}

	//Should send a CLI_REL_BLAME
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_BLAME to the relay")
	}

	msg12 := sentToRelay[0].(*net.CLI_REL_BLAME)
	sentToRelay = make([]interface{}, 0)
	if msg12.RoundID != 1 {
		t.Error("Client should have sent a BLAME for round 1")
	}
	if msg12.BitPos != 23 { //added a 1 in the last position of 3rd bit
		t.Error("Client sent wrong bitPos")
	}

	msg13 := net.REL_ALL_REVEAL{
		RoundID: 1,
		BitPos:  23}
	err13 := client.ReceivedMessage(msg13)
	if err13 != nil {
		t.Error("Client should be able to receive this data")
	}

	//Should send a CLI_REL_REVEAL
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_REVEAL to the relay")
	}

	msg14 := sentToRelay[0].(*net.CLI_REL_REVEAL)
	sentToRelay = make([]interface{}, 0)
	if msg14.ClientID != clientID {
		t.Error("CLient sent wrong ID")
	}

	msg15 := net.REL_ALL_SECRET{
		UserID: 1}
	err15 := client.ReceivedMessage(msg15)
	if err15 != nil {
		t.Error("Client should be able to receive this data")
	}

	//Should send a CLI_REL_SECRET
	if len(sentToRelay) == 0 {
		t.Error("Client should have sent a CLI_REL_SECRET to the relay")
	}

	msg16 := sentToRelay[0].(*net.CLI_REL_SECRET)
	sentToRelay = make([]interface{}, 0)
	if msg16.Secret == nil {
		t.Error("Client sent empty secret")
	}
}
