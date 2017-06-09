package prifi_lib

import (
	"github.com/lbarman/prifi/prifi-lib/client"
	"github.com/lbarman/prifi/prifi-lib/net"
	"github.com/lbarman/prifi/prifi-lib/relay"
	"github.com/lbarman/prifi/prifi-lib/trustee"
	"gopkg.in/dedis/onet.v1/log"
)

/*
PriFi - Library
***************
This is a network-agnostic PriFi library. Feed it with a MessageSender interface (that knows how to contact the different entities),
and call ReceivedMessage(msg) with the received messages.
Then, it runs the PriFi anonymous communication network among those entities.
*/

// PriFiLibInstance contains the mutable state of a PriFi entity.
type PriFiLibInstance struct { //todo remove this, like it was done for client
	role                   int16
	messageSender          net.MessageSender
	specializedLibInstance SpecializedLibInstance
}

//Prifi's "Relay", "Client" and "Trustee" instance all can receive a message
type SpecializedLibInstance interface {
	ReceivedMessage(msg interface{}) error
}

// Possible role of PriFi entities.
// The role restricts the kind of messages an entity can receive at
// a given point in time. The roles are mutually exclusive.
const (
	PRIFI_ROLE_UNDEFINED int16 = iota
	PRIFI_ROLE_RELAY
	PRIFI_ROLE_CLIENT
	PRIFI_ROLE_TRUSTEE
)

// NewPriFiClient creates a new PriFi client
func NewPriFiClient(doLatencyTest bool, dataOutputEnabled bool, dataForDCNet chan []byte, dataFromDCNet chan []byte, doReplayPcap bool, pcapFolder string, msgSender net.MessageSender) *PriFiLibInstance {
	msw := newMessageSenderWrapper(msgSender)
	c := client.NewClient(doLatencyTest, dataOutputEnabled, dataForDCNet, dataFromDCNet, doReplayPcap, pcapFolder, msw)
	p := &PriFiLibInstance{
		role: PRIFI_ROLE_CLIENT,
		specializedLibInstance: c,
		messageSender:          msgSender,
	}
	return p
}

// NewPriFiRelay creates a new PriFi relay
func NewPriFiRelay(dataOutputEnabled bool, dataForClients chan []byte, dataFromDCNet chan []byte, experimentResultChan chan interface{}, timeoutHandler func([]int, []int), msgSender net.MessageSender) *PriFiLibInstance {
	msw := newMessageSenderWrapper(msgSender)
	r := relay.NewRelay(dataOutputEnabled, dataForClients, dataFromDCNet, experimentResultChan, timeoutHandler, msw)
	p := &PriFiLibInstance{
		role: PRIFI_ROLE_RELAY,
		specializedLibInstance: r,
		messageSender:          msgSender,
	}
	return p
}

// NewPriFiTrustee creates a new PriFi trustee
func NewPriFiTrustee(msgSender net.MessageSender) *PriFiLibInstance {
	//msw := newMessageSenderWrapper(msgSender)

	errHandling := func(e error) { /* do nothing yet, we are alerted of errors via the SDA */ }
	loggingSuccessFunction := func(e interface{}) { log.Lvl5(e) }
	loggingErrorFunction := func(e interface{}) { log.Error(e) }

	msw, err := net.NewMessageSenderWrapper(true, loggingSuccessFunction, loggingErrorFunction, errHandling, msgSender)
	if err != nil {
		log.Fatal("Could not create a MessageSenderWrapper, error is", err)
	}

	t := trustee.NewTrustee(msw)
	p := &PriFiLibInstance{
		role: PRIFI_ROLE_TRUSTEE,
		specializedLibInstance: t,
		messageSender:          msgSender,
	}
	return p
}

// ReceivedMessage must be called when a PriFi host receives a message.
// It takes care to call the correct message handler function.
func (p *PriFiLibInstance) ReceivedMessage(msg interface{}) error {
	err := p.specializedLibInstance.ReceivedMessage(msg)
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func newMessageSenderWrapper(msgSender net.MessageSender) *net.MessageSenderWrapper {

	errHandling := func(e error) { /* do nothing yet, we are alerted of errors via the SDA */ }
	loggingSuccessFunction := func(e interface{}) { log.Lvl3(e) }
	loggingErrorFunction := func(e interface{}) { log.Error(e) }

	msw, err := net.NewMessageSenderWrapper(true, loggingSuccessFunction, loggingErrorFunction, errHandling, msgSender)
	if err != nil {
		log.Fatal("Could not create a MessageSenderWrapper, error is", err)
	}
	return msw
}
