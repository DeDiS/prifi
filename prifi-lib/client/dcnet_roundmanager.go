package client

import (
	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/dcnet"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
	"math"
	"sync"
)

// DCNet_RoundManager allows to request DC-net pads for a specific round
type DCNet_RoundManager struct {
	sync.Mutex
	CellCoder     dcnet.CellCoder
	currentRound  int32
	sharedSecrets []abstract.Point
}

// ClientSetup stores the sharedSecrets to be able to reveal bits in case of disruption
func (dc *DCNet_RoundManager) ClientSetup(sharedSecrets []abstract.Point) {
	dc.sharedSecrets = sharedSecrets
}

// ClientEncodeForRound allows to request DC-net pads for a specific round
func (dc *DCNet_RoundManager) ClientEncodeForRound(roundID int32, payload []byte, payloadSize int, history abstract.Cipher) []byte {
	dc.Lock()
	defer dc.Unlock()

	for dc.currentRound < roundID {
		//discard crypto material
		log.Lvl4("Discarding round", dc.currentRound)
		_ = dc.CellCoder.ClientEncode(nil, payloadSize, history)
		dc.currentRound++
	}

	log.Lvl4("Producing round", dc.currentRound)
	//produce the real round
	data := dc.CellCoder.ClientEncode(payload, payloadSize, history)
	dc.currentRound++
	return data
}

// RevealBits reveals the individual bits from each cipher in case of disruption
func (dc *DCNet_RoundManager) RevealBits(roundID int32, bitPos int, payloadLength int) map[int]int {
	dc.Lock()
	defer dc.Unlock()
	round_ID := roundID
	if round_ID > dc.currentRound {
		log.Fatal("Trying to reveal a future round")
	}
	var bits map[int]int
	bits = make(map[int]int)

	sharedPRNGs := make([]abstract.Cipher, len(dc.sharedSecrets))
	for i := 0; i < len(dc.sharedSecrets); i++ {
		bytes, err := dc.sharedSecrets[i].MarshalBinary()
		if err != nil {
			log.Fatal("Could not marshal point !")
		}
		sharedPRNGs[i] = config.CryptoSuite.Cipher(bytes)
	}
	npeers := len(sharedPRNGs)
	dcCiphers := make([]abstract.Cipher, npeers)
	for i := range sharedPRNGs {
		key := make([]byte, config.CryptoSuite.Cipher(nil).KeySize())
		sharedPRNGs[i].Partial(key, key, nil)
		dcCiphers[i] = config.CryptoSuite.Cipher(key)
	}

	for i := int32(0); i < round_ID; i++ {
		//discard crypto material
		dst := make([]byte, payloadLength)
		for i := range dcCiphers {
			dcCiphers[i].Read(dst)
		}
	}

	for i := range dcCiphers {
		dst := make([]byte, payloadLength)
		dcCiphers[i].Read(dst)
		m := float64(bitPos) / float64(8)
		m = math.Floor(m)
		m2 := int(m)
		n := bitPos % 8
		mask := byte(1 << uint8(n))
		if (dst[m2] & mask) == 0 {
			bits[i] = 0
		} else {
			bits[i] = 1
		}
	}
	return bits
}
