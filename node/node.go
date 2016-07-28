package node

import (
	"github.com/lbarman/prifi/config"
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
