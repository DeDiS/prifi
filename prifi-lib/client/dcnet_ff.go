package client

import (
	"github.com/lbarman/prifi/prifi-lib/dcnet"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
)

type DCNet_FastForwarder struct {
	CellCoder                 dcnet.CellCoder
	currentRound int32
}

func (dc *DCNet_FastForwarder) ClientEncodeForRound(roundID int32, payload []byte, payloadSize int,  history abstract.Cipher) []byte {

	for dc.currentRound < roundID {
		//discard crypto material
		log.Error("Discarding round", dc.currentRound)
		_ = dc.CellCoder.ClientEncode(nil, payloadSize, history)
		dc.currentRound++
	}

	log.Error("Producing round", dc.currentRound)
	//produce the real round
	data := dc.CellCoder.ClientEncode(payload, payloadSize, history)
	dc.currentRound++
	return data
}