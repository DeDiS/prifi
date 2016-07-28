package client

import (
	"fmt"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"time"
	"github.com/lbarman/prifi/node"
)

const MaxUint uint32 = uint32(4294967295)

// Number of bytes of cell payload to reserve for connection header, length
const socksHeaderLength = 6

const WAIT_FOR_PUBLICKEY_SLEEP_TIME = 100 * time.Millisecond
const FAILED_CONNECTION_WAIT_BEFORE_RETRY = 1000 * time.Millisecond
const UDP_DATAGRAM_WAIT_TIMEOUT = 5 * time.Second

type ParamsFromRelay struct {
	trusteesPublicKeys []abstract.Point
	nClients           int
}

type ClientState struct {
	node.NodeState

	UsablePayloadLength int
	UseSocksProxy       bool
	LatencyTest         bool
	UseUDP              bool

	TrusteePublicKey    []abstract.Point
}

func (clientState *ClientState) printSecrets() {
	//print all secrets


	k1, _ := clientState.NodeState.PublicKey.MarshalBinary()
	k2, _ := clientState.NodeState.PrivateKey.MarshalBinary()
	var k3, k4 []byte

	if clientState.NodeState.EphemeralPublicKey != nil {
		k3, _ = clientState.NodeState.EphemeralPublicKey.MarshalBinary()
		k4, _ = clientState.NodeState.EphemeralPrivateKey.MarshalBinary()
	}

	fmt.Println("")
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	fmt.Println("            CLIENT ", clientState.NodeState.Id)
	fmt.Println("Public key :")
	fmt.Println(hex.Dump(k1))
	fmt.Println("private key :")
	fmt.Println(hex.Dump(k2))

	if clientState.NodeState.EphemeralPublicKey != nil {
		fmt.Println("Ephemeral public key :")
		fmt.Println(hex.Dump(k3))
		fmt.Println("Ephemeral private key :")
		fmt.Println(hex.Dump(k4))
	}

	for i := 0; i < clientState.NodeState.NumTrustees; i++ {
		fmt.Println("> > > > > > > > > > > > > > > > >")
		fmt.Println("   Shared Params With Trustee", i)
		d1, _ := clientState.TrusteePublicKey[i].MarshalBinary()
		//d2, _ := clientState.NodeState.SharedSecrets[i].MarshalBinary()
		fmt.Println("Trustee public key :")
		fmt.Println(hex.Dump(d1))
		//fmt.Println("Shared secret :")
		//fmt.Println(hex.Dump(d2))
	}
	fmt.Println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
	fmt.Println("")
}