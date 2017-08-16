package client

import (
	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/crypto"
	"github.com/lbarman/prifi/prifi-lib/dcnet"
	"gopkg.in/dedis/crypto.v0/abstract"
	"testing"
)

func TestDCNetRoundManager(test *testing.T) {
	dc := new(DCNet_RoundManager)
	dc.CellCoder = dcnet.SimpleCoderFactory()

	dc2 := new(DCNet_RoundManager)
	dc2.CellCoder = dcnet.SimpleCoderFactory()

	//set up the DC-nets
	_, clientp := crypto.NewKeyPair()
	trusteeP, _ := crypto.NewKeyPair()
	sharedSecret := config.CryptoSuite.Point().Mul(trusteeP, clientp)
	sharedPRNGs := make([]abstract.Cipher, 1)
	sharedPRNGs2 := make([]abstract.Cipher, 1)
	bytes, err := sharedSecret.MarshalBinary()
	if err != nil {
		test.Fatal("Could not marshal point !")
	}
	sharedPRNGs[0] = config.CryptoSuite.Cipher(bytes)
	sharedPRNGs2[0] = config.CryptoSuite.Cipher(bytes)

	sharedSecrets := make([]abstract.Point, 1)
	sharedSecrets[0] = sharedSecret
	dc2.ClientSetup(sharedSecrets)
	dc.CellCoder.ClientSetup(config.CryptoSuite, sharedPRNGs)
	dc2.CellCoder.ClientSetup(config.CryptoSuite, sharedPRNGs2)

	cellSize := 8
	//var history abstract.Cipher
	history := config.CryptoSuite.Cipher([]byte("init"))

	//the "real" rounds
	round0 := dc.CellCoder.ClientEncode(nil, cellSize, history)
	_ = dc.CellCoder.ClientEncode(nil, cellSize, history)
	round2 := dc.CellCoder.ClientEncode(nil, cellSize, history)
	_ = dc.CellCoder.ClientEncode(nil, cellSize, history)
	round4 := dc.CellCoder.ClientEncode(nil, cellSize, history)

	//the skipped rounds
	round02 := dc2.ClientEncodeForRound(0, nil, cellSize, history)
	round22 := dc2.ClientEncodeForRound(2, nil, cellSize, history)
	round42 := dc2.ClientEncodeForRound(4, nil, cellSize, history)

	if !testEq(round0, round02) {
		test.Error("Round 0 should be the same at both places")
	}
	if !testEq(round2, round22) {
		test.Error("Round 2 should be the same at both places")
	}
	if !testEq(round4, round42) {
		test.Error("Round 4 should be the same at both places")
	}

	for i := 0; i < 8; i++ {
		mask := byte(1 << uint8(i))
		revealed_bit := dc2.RevealBits(2, i, cellSize)[0]
		if (((round22[0] & mask) == 0) && (revealed_bit != 0)) || (((round22[0] & mask) != 0) && (revealed_bit == 0)) {
			test.Error("problem with revealed bits ")
		}
	}
}

func testEq(a, b []byte) bool {

	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
