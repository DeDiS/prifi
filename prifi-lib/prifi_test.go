package prifi_lib

import (
	"errors"
	"github.com/lbarman/prifi/prifi-lib/crypto"
	"github.com/lbarman/prifi/prifi-lib/net"
	"gopkg.in/dedis/onet.v1/log"
	"testing"
)

/**
 * Message Sender
 */
type TestMessageSender struct {
}

func (t *TestMessageSender) SendToClient(i int, msg interface{}) error {
	return nil
}
func (t *TestMessageSender) SendToTrustee(i int, msg interface{}) error {
	return errors.New("not implemented")
}
func (t *TestMessageSender) SendToRelay(msg interface{}) error {
	return errors.New("not implemented")
}
func (t *TestMessageSender) BroadcastToAllClients(msg interface{}) error {
	return errors.New("not implemented")
}
func (t *TestMessageSender) ClientSubscribeToBroadcast(clientName string, messageReceived func(interface{}) error, startStopChan chan bool) error {
	return errors.New("not implemented")
}

func TestPrifi(t *testing.T) {

	msgSender := new(TestMessageSender)
	in := make(chan []byte, 6)
	out := make(chan []byte, 3)

	client0 := NewPriFiClient(true, true, in, out, msgSender)
	client1 := NewPriFiClient(true, true, in, out, msgSender)

	timeoutHandler := func(clients, trustees []int) { log.Error(clients, trustees) }
	resultChan := make(chan interface{}, 1)

	relay := NewPriFiRelay(true, in, out, resultChan, timeoutHandler, msgSender)

	trustee0 := NewPriFiTrustee(msgSender)
	trustee1 := NewPriFiTrustee(msgSender)

	//TODO : emulate network connectivity, and run for a few rounds

	//should trigger an error, not ready
	pub, _ := crypto.NewKeyPair()
	relay.ReceivedMessage(net.TRU_REL_TELL_PK{Pk: pub})

	//emulate the reception of a ALL_ALL_PARAMETERS with StartNow=true
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.Add("StartNow", true)
	msg.Add("NTrustees", 2)
	msg.Add("NClients", 2)
	msg.Add("UpstreamCellSize", 1000)
	msg.Add("DownstreamCellSize", 1000)
	msg.Add("WindowSize", 1)
	msg.Add("UseDummyDataDown", true)
	msg.Add("ExperimentRoundLimit", 10)
	msg.Add("UseUDP", false)
	msg.ForceParams = true

	relay.ReceivedMessage(*msg)
	_ = client0
	_ = client1
	_ = relay
	_ = trustee0
	_ = trustee1
}
