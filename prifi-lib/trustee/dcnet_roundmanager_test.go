package trustee

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
	dc.TrusteeSetup(sharedSecrets)
	dc.CellCoder.TrusteeSetup(config.CryptoSuite, sharedPRNGs)

	cellSize := 8

	//the "real" rounds
	round0 := dc.TrusteeEncode(cellSize)
	_ = dc.TrusteeEncode(cellSize)
	round2 := dc.TrusteeEncode(cellSize)
	_ = dc.TrusteeEncode(cellSize)

	for i := 0; i < 8; i++ {
		mask := byte(1 << uint8(i))
		revealed_bit := dc.RevealBits(2, i, cellSize)[0]
		if (((round2[0] & mask) == 0) && (revealed_bit != 0)) || (((round2[0] & mask) != 0) && (revealed_bit == 0)) {
			test.Error("problem with revealed bits ")
		}
		revealed_bit2 := dc.RevealBits(0, i, cellSize)[0]
		if (((round0[0] & mask) == 0) && (revealed_bit2 != 0)) || (((round0[0] & mask) != 0) && (revealed_bit2 == 0)) {
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
