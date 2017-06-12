package net

import (
	"bytes"
	"errors"
	"github.com/lbarman/prifi/prifi-lib/crypto"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"testing"
)

type TestMessageSender struct {
}

func (t *TestMessageSender) SendToClient(i int, msg interface{}) error {
	return errors.New("Tried to send to client!")
}
func (t *TestMessageSender) SendToTrustee(i int, msg interface{}) error {
	return nil
}
func (t *TestMessageSender) SendToRelay(msg interface{}) error {
	if msg == "trigger-error" {
		return errors.New("error triggered")
	}
	return nil
}
func (t *TestMessageSender) BroadcastToAllClients(msg interface{}) error {
	return nil
}
func (t *TestMessageSender) ClientSubscribeToBroadcast(clientID int, messageReceived func(interface{}) error, startStopChan chan bool) error {
	return nil
}

func TestMessageSenderWrapper(t *testing.T) {

	_, err := NewMessageSenderWrapper(true, nil, nil, nil, nil)
	if err == nil {
		t.Error("If logging=true, should provide a logging function")
	}
	_, err = NewMessageSenderWrapper(true, func(interface{}) {}, nil, nil, nil)
	if err == nil {
		t.Error("If logging=true, should provide a logging function")
	}

	_, err = NewMessageSenderWrapper(false, nil, nil, nil, nil)
	if err == nil {
		t.Error("Should provide a error handling function")
	}

	errHandling := func(e error) {}
	_, err = NewMessageSenderWrapper(false, nil, nil, errHandling, nil)
	if err == nil {
		t.Error("Should provide a messageSender")
	}

	//test the real stuff
	var errorHandlerCalled bool = false
	errHandling = func(e error) { errorHandlerCalled = true }
	msgSender := new(TestMessageSender)
	msw, err := NewMessageSenderWrapper(false, nil, nil, errHandling, msgSender)
	if err != nil {
		t.Error("Should be able to create a MessageSenderWrapper")
	}

	success := msw.SendToTrusteeWithLog(0, "hello", "")
	if !success || errorHandlerCalled {
		t.Error("this call should not trigger an error")
	}
	var loggingFunctionCalled bool = false
	logging := func(e interface{}) { loggingFunctionCalled = true }
	msw, err = NewMessageSenderWrapper(true, logging, logging, errHandling, msgSender)

	if err != nil {
		t.Error("Shouldn't have an error here," + err.Error())
	}

	success = msw.SendToClientWithLog(0, "hello", "")
	if success || !errorHandlerCalled {
		t.Error("this call should trigger an error")
	}
}

func TestMessageSenderWrapperRelay(t *testing.T) {

	//test the real stuff
	var errorHandlerCalled bool = false
	var loggingFunctionCalled bool = false

	errHandling := func(e error) { errorHandlerCalled = true }
	logging := func(e interface{}) { loggingFunctionCalled = true }

	msgSender := new(TestMessageSender)
	msw, err := NewMessageSenderWrapper(true, logging, logging, errHandling, msgSender)
	if err != nil {
		t.Error("Should be able to create a MessageSenderWrapper")
	}

	success := msw.SendToTrusteeWithLog(0, "hello", "")
	if !success || errorHandlerCalled {
		t.Error("this call should not trigger an error")
	}
	errorHandlerCalled = false
	success = msw.SendToRelayWithLog("hello", "")
	if !success || errorHandlerCalled {
		t.Error("this call should not trigger an error")
	}
	errorHandlerCalled = false
	success = msw.SendToRelayWithLog("trigger-error", "")
	if success || !errorHandlerCalled {
		t.Error("this call should trigger an error")
	}
}

func TestTELL_TRANSCRIPT_Message(t *testing.T) {

	msg := new(REL_TRU_TELL_TRANSCRIPT)
	pks := make([]abstract.Point, 2)
	pks[0], _ = crypto.NewKeyPair()
	pks[1], _ = crypto.NewKeyPair()
	msg.EphPks = make([]PublicKeyArray, 1)
	msg.EphPks[0] = PublicKeyArray{Keys: pks}

	bytes := make([]byte, 4)
	msg.Proofs = make([]ByteArray, 1)
	msg.Proofs[0] = ByteArray{Bytes: bytes}

	msg.GetKeys()

	msg.GetProofs()

}

func TestUDPMessage(t *testing.T) {

	msg := new(REL_CLI_DOWNSTREAM_DATA_UDP)

	//random content
	content := new(REL_CLI_DOWNSTREAM_DATA)
	content.RoundID = 1
	content.FlagResync = true
	content.Data = random.Bits(100, false, random.Stream)
	content.FlagOpenClosedRequest = true
	content.HashRoundID = 1
	content.Hash = random.Bits(256, false, random.Stream)

	msg.SetContent(*content)

	//test marshalling
	msgBytes, err := msg.ToBytes()

	if err != nil {
		t.Error(err)
	}
	if msgBytes == nil {
		t.Error("msgBytes can't be nil")
	}

	void := new(REL_CLI_DOWNSTREAM_DATA_UDP)
	msg2, err2 := void.FromBytes(msgBytes)

	if err2 != nil {
		t.Error(err2)
	}

	parsedMsg := msg2.(REL_CLI_DOWNSTREAM_DATA_UDP)

	if parsedMsg.RoundID != content.RoundID {
		t.Error("RoundID unparsed incorrectly")
	}
	if parsedMsg.HashRoundID != content.HashRoundID {
		t.Error("HashRoundID unparsed incorrectly")
	}
	if parsedMsg.FlagResync != content.FlagResync {
		t.Error("FlagResync unparsed incorrectly")
	}
	if !bytes.Equal(parsedMsg.Data, content.Data) {
		t.Error("Data unparsed incorrectly")
	}
	if !bytes.Equal(parsedMsg.Hash, content.Hash) {
		t.Error("Hash unparsed incorrectly")
	}

	//this should fail, cannot read the size if len<4
	void = new(REL_CLI_DOWNSTREAM_DATA_UDP)
	void.Print()
	_, err2 = void.FromBytes(msgBytes[0:3])

	if err2 == nil {
		t.Error("REL_CLI_DOWNSTREAM_DATA_UDP should not allow to decode message < 4 bytes")
	}
}
