package node

import (
	"github.com/lbarman/prifi/config"
	"github.com/dedis/crypto/abstract"
)

func InitNodeState(nodeConfig config.NodeConfig, nClients int, nTrustees int, cellSize int) NodeState {

	nodeState := new(NodeState)

	nodeState.Name = nodeConfig.Name
	nodeState.Id = nodeConfig.Id

	nodeState.NumClients = nClients
	nodeState.NumTrustees = nTrustees

	nodeState.PublicKey = nodeConfig.PublicKey
	nodeState.PrivateKey = nodeConfig.PrivateKey

	nodeState.CellSize = cellSize
	nodeState.CellCoder = config.Factory()
	return *nodeState
}

func UpdateMessageHistory(history abstract.Cipher, newMessage []byte) abstract.Cipher {

	var newHistory []byte
	if history.CipherState == nil {		// If the history is empty
		if len(newMessage) == 0 {
			newMessage = []byte("dummy")   // Initial history
		}
		newHistory = make([]byte, len(newMessage))
		copy(newHistory, newMessage)
	} else {
		s := config.CryptoSuite.Scalar().Pick(history)
		historyBytes, _ := s.MarshalBinary()
		newHistory = make([]byte, len(historyBytes) + len(newMessage))

		copy(newHistory[:len(historyBytes)], historyBytes)
		copy(newHistory[len(historyBytes):], newMessage)
	}
	return config.CryptoSuite.Cipher(newHistory)
}
