package node

import (
	"github.com/dedis/crypto/abstract"
	"github.com/lbarman/prifi/config"
	"github.com/lbarman/prifi/dcnet"
)

type NodeState struct {
	Id   int
	Name string

	PublicKey  abstract.Point
	PrivateKey abstract.Scalar

	EphemeralPublicKey  abstract.Point
	EphemeralPrivateKey abstract.Scalar

	NumClients  int
	NumTrustees int

	CellSize      int // Payload length
	SharedSecrets []abstract.Cipher

	CellCoder      dcnet.CellCoder
	MessageHistory abstract.Cipher
}

func (nodeState *NodeState) GenerateEphemeralKeys() {

	// Prepare crypto parameters
	rand := config.CryptoSuite.Cipher([]byte(nodeState.Name))
	base := config.CryptoSuite.Point().Base()

	// Generate ephemeral keys
	Epriv := config.CryptoSuite.Scalar().Pick(rand)
	Epub := config.CryptoSuite.Point().Mul(base, Epriv)

	nodeState.EphemeralPublicKey = Epub
	nodeState.EphemeralPrivateKey = Epriv
}
