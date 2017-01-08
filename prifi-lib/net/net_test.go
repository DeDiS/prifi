package net

import (
	"bytes"
	"github.com/dedis/crypto/random"
	"testing"
)

func TestUDPMessage(t *testing.T) {

	msg := new(REL_CLI_DOWNSTREAM_DATA_UDP)

	//random content
	content := new(REL_CLI_DOWNSTREAM_DATA)
	content.RoundID = 1
	content.FlagResync = true
	content.Data = random.Bits(100, false, random.Stream)

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
	if parsedMsg.FlagResync != content.FlagResync {
		t.Error("FlagResync unparsed incorrectly")
	}
	if !bytes.Equal(parsedMsg.Data, content.Data) {
		t.Error("Data unparsed incorrectly")
	}
}