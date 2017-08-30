package utils

import (
"testing"
	"github.com/lbarman/prifi/prifi-lib/dcnet"
	"github.com/lbarman/prifi/prifi-lib/crypto"
	"github.com/lbarman/prifi/prifi-lib/config"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
)

func TestEquivocation(t *testing.T) {

	//ntrustee := 1
	//nclients := 2
	cellSize := 64

	//history := Hash(make([]byte, 10))
	history := config.CryptoSuite.Cipher([]byte("init"))

	//set up the DC-nets
	tpub,_ := crypto.NewKeyPair()
	_,c1priv := crypto.NewKeyPair()
	_,c2priv := crypto.NewKeyPair()

	sharedSecret_c1 := config.CryptoSuite.Point().Mul(tpub, c1priv)
	sharedSecret_c2 := config.CryptoSuite.Point().Mul(tpub, c2priv)

	sharedPRNGs_t := make([]abstract.Cipher, 2)
	sharedPRNGs_c1 := make([]abstract.Cipher, 1)
	sharedPRNGs_c2 := make([]abstract.Cipher, 1)

	bytes, err := sharedSecret_c1.MarshalBinary()
	if err != nil {
		t.Error("Could not marshal point !")
	}
	sharedPRNGs_c1[0] = config.CryptoSuite.Cipher(bytes)
	sharedPRNGs_t[0] = config.CryptoSuite.Cipher(bytes)
	bytes, err = sharedSecret_c2.MarshalBinary()
	if err != nil {
		t.Error("Could not marshal point !")
	}
	sharedPRNGs_c2[0] = config.CryptoSuite.Cipher(bytes)
	sharedPRNGs_t[1] = config.CryptoSuite.Cipher(bytes)

	cellCodert := dcnet.SimpleCoderFactory()
	cellCodert.TrusteeSetup(config.CryptoSuite, sharedPRNGs_t)

	cellCoderc1 := dcnet.SimpleCoderFactory()
	cellCoderc1.ClientSetup(config.CryptoSuite, sharedPRNGs_c1)

	cellCoderc2 := dcnet.SimpleCoderFactory()
	cellCoderc2.ClientSetup(config.CryptoSuite, sharedPRNGs_c2)

	data := make([]byte, 0)
	padRound1_c1 := cellCoderc1.ClientEncode(data, cellSize, history)
	padRound1_c2 := cellCoderc2.ClientEncode(data, cellSize, history)
	padRound2_t := cellCodert.TrusteeEncode(cellSize)

	res := make([]byte, cellSize)
	for i := range padRound1_c2 {
		v := padRound1_c1[i]
		v ^= padRound1_c2[i] ^ padRound2_t[i]
		res[i] = v
	}

	payload := make([]byte, cellSize)
	payload[0] = 0
	payload[1] = 1
	payload[2] = 2

	historyBytes := make([]byte, 10)
	historyBytes[1] = 1

	e := new(Equivocation)

	pads1 := make([][]byte, 1)
	pads1[0] = padRound1_c1
	x_prim1, kappa1 := e.ClientEncryptPayload(payload, historyBytes, pads1)

	log.Lvl1("----------------")
	pads2 := make([][]byte, 1)
	pads2[0] = padRound1_c2
	_, kappa2 := e.ClientEncryptPayload(nil, historyBytes, pads2)

	log.Lvl1("----------------")

	pads3 := make([][]byte, 2)
	pads3[0] = padRound1_c1
	pads3[1] = padRound1_c2
	sigma := e.TrusteeGetContribution(pads3)

	log.Lvl1(sigma)
	log.Lvl1("----------------")

	// relay decodes
	trusteesContrib := make([][]byte, 1)
	trusteesContrib[0] = sigma

	clientContrib := make([][]byte, 2)
	clientContrib[0] = kappa1
	clientContrib[1] = kappa2

	payloadPlaintext := e.RelayDecode(x_prim1, historyBytes, trusteesContrib,clientContrib)

	log.Lvl1(payloadPlaintext)
}