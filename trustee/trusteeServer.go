package trustee

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/dedis/crypto/abstract"
	crypto_proof "github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
	"github.com/lbarman/prifi/config"
	"github.com/lbarman/prifi/crypto"
	prifilog "github.com/lbarman/prifi/log"
	prifinet "github.com/lbarman/prifi/net"
	"github.com/lbarman/prifi/node"
	"github.com/lbarman/prifi/auth"
)

func StartTrustee(nodeConfig config.NodeConfig) {

	prifilog.SimpleStringDump(prifilog.NOTIFICATION, "Trustee server started")

	// async listen for incoming connections
	newConnections := make(chan net.Conn)
	go startListening(TRUSTEE_SERVER_LISTENING_PORT, newConnections)

	activeConnections := make([]net.Conn, 0)

	// handler warns the handler when a connection closes
	closedConnections := make(chan int)

	for {
		select {

		// New TCP connection
		case newConn := <-newConnections:
			activeConnections = append(activeConnections, newConn)
			go handleConnection(nodeConfig, newConn, closedConnections)
		}
	}
}

func startListening(listenport string, newConnections chan<- net.Conn) {
	prifilog.SimpleStringDump(prifilog.NOTIFICATION, "Listening on port "+listenport)

	lsock, err := net.Listen("tcp", listenport)

	if err != nil {
		prifilog.SimpleStringDump(prifilog.SEVERE_ERROR, "Failed listening "+err.Error())
		return
	}
	for {
		conn, err := lsock.Accept()
		prifilog.SimpleStringDump(prifilog.INFORMATION, "Accepted on port "+listenport)

		if err != nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Accept error "+err.Error())
			lsock.Close()
			return
		}
		newConnections <- conn
	}
}

func handleConnection(nodeConfig config.NodeConfig, conn net.Conn, closedConnections chan int) {

	defer conn.Close()

	// Read the incoming connection into the buffer
	buffer, err := prifinet.ReadMessage(conn)
	if err != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, nodeConfig.Name + "; Error reading " + err.Error())
		return
	}

	// Extract the global parameters
	cellSize := int(binary.BigEndian.Uint32(buffer[0:4]))
	nClients := int(binary.BigEndian.Uint32(buffer[4:8]))
	nTrustees := int(binary.BigEndian.Uint32(buffer[8:12]))

	prifilog.SimpleStringDump(prifilog.INFORMATION, nodeConfig.Name +
		" setup is " + strconv.Itoa(nClients) + " clients " + strconv.Itoa(nTrustees) +
		" trustees, cellSize " + strconv.Itoa(cellSize))

	trusteeState := new(TrusteeState)
	trusteeState.NodeState = node.InitNodeState(nodeConfig, nClients, nTrustees, cellSize)
	trusteeState.activeConnection = conn
	trusteeState.ClientPublicKeys = make([]abstract.Point, nClients)

	// Run the authentication protocol
	if err = auth.ClientAuthentication(nodeConfig.AuthMethod, conn, trusteeState.Id, trusteeState.PrivateKey); err != nil {
		prifilog.SimpleStringDump(prifilog.SEVERE_ERROR, "Trustee authentication failed. " + err.Error())
	}
	prifilog.SimpleStringDump(prifilog.INFORMATION, "Authenticated successfully.")

	// Read the clients' public keys from the connection
	clientsPublicKeys, err := prifinet.UnMarshalPublicKeyArrayFromConnection(conn, config.CryptoSuite)

	if err != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Error reading public keys "+err.Error())
		return
	}

	// Create a shared secret with every client
	trusteeState.NodeState.SharedSecrets = make([]abstract.Cipher, len(clientsPublicKeys))
	for i := 0; i < len(clientsPublicKeys); i++ {
		trusteeState.ClientPublicKeys[i] = clientsPublicKeys[i]
		sharedPoint := config.CryptoSuite.Point().Mul(clientsPublicKeys[i], trusteeState.NodeState.PrivateKey)
		sharedBytes, _ := sharedPoint.MarshalBinary()
		trusteeState.NodeState.SharedSecrets[i] = config.CryptoSuite.Cipher(sharedBytes)
	}

	// Check that we got all keys
	for i := 0; i < nClients; i++ {
		if trusteeState.ClientPublicKeys[i] == nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Didn't get public keys from client "+strconv.Itoa(i))
			return
		}
	}

	//print all shared secrets
	for i := 0; i < nClients; i++ {
		fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
		fmt.Println("            Client", i)
		d1, _ := trusteeState.ClientPublicKeys[i].MarshalBinary()
		//d2, _ := trusteeState.NodeState.SharedSecrets[i].MarshalBinary()
		fmt.Println(hex.Dump(d1))
		//fmt.Println("+++")
		//fmt.Println(hex.Dump(d2))
		fmt.Println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
	}

	// Initialize cell coder
	trusteeState.NodeState.CellCoder.TrusteeSetup(config.CryptoSuite, trusteeState.NodeState.SharedSecrets)

	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.NodeState.Name + "; All crypto stuff exchanged ! ")
	//parse the ephemeral keys
	base, ephPublicKeys, err := prifinet.ParseBaseAndPublicKeysFromConn(conn)

	if err != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Error parsing ephemeral keys, quitting. "+err.Error())
		return
	}

	//do the round-shuffle

	rand := config.CryptoSuite.Cipher([]byte(trusteeState.NodeState.Name))
	H := trusteeState.NodeState.PublicKey
	X := ephPublicKeys
	Y := X

	if len(ephPublicKeys) > 1 {
		_, _, prover := shuffle.Shuffle(config.CryptoSuite, nil, H, X, Y, rand)
		_, err = crypto_proof.HashProve(config.CryptoSuite, "PairShuffle", rand, prover)
	}
	if err != nil {
		//prifilog.SimpleStringDump("Trustee " + strconv.Itoa(connId) + "; Shuffle proof failed. "+err.Error())
		return
	}

	//base2, ephPublicKeys2, proof := NeffShuffle(base, ephPublicKey)
	base2 := base
	ephPublicKeys2 := ephPublicKeys
	proof := make([]byte, 50)

	//Send back the shuffle
	prifinet.WriteBasePublicKeysAndProofToConn(conn, base2, ephPublicKeys2, proof)
	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.NodeState.Name + "; Shuffling done, wrote back to the relay ")

	//we wait, verify, and sign the transcript
	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.NodeState.Name + "; Parsing the transcript ...")

	G_s, ephPublicKeys_s, proof_s, err := prifinet.ParseTranscript(conn, nClients, nTrustees)

	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.NodeState.Name + "; Verifying the transcript... ")

	//Todo : verify each individual permutations
	for j := 0; j < nTrustees; j++ {

		verify := true
		if j > 0 {
			H := G_s[j]
			X := ephPublicKeys_s[j-1]
			Y := ephPublicKeys_s[j-1]
			Xbar := ephPublicKeys_s[j]
			Ybar := ephPublicKeys_s[j]
			if len(X) > 1 {
				verifier := shuffle.Verifier(config.CryptoSuite, nil, H, X, Y, Xbar, Ybar)
				err = crypto_proof.HashVerify(config.CryptoSuite, "PairShuffle", verifier, proof_s[j])
			}
			if err != nil {
				verify = false
			}
		}
		verify = true

		if !verify {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Transcript invalid for trustee "+strconv.Itoa(j)+". Aborting.")
			return
		}
	}

	//we verify that our shuffle was included
	ownPermutationFound := false
	for j := 0; j < nTrustees; j++ {

		if G_s[j].Equal(base2) && bytes.Equal(proof, proof_s[j]) {
			prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.NodeState.Name + "; Find in transcript : Found indice "+strconv.Itoa(j)+" that seems to match, verifing all the keys...")
			allKeyEqual := true
			for k := 0; k < nClients; k++ {
				if !ephPublicKeys2[k].Equal(ephPublicKeys_s[j][k]) {
					prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Transcript invalid for trustee "+strconv.Itoa(j)+". Aborting.")
					allKeyEqual = false
					break
				}
			}

			if allKeyEqual {
				ownPermutationFound = true
			}
		}
	}

	if !ownPermutationFound {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Can't find own transaction. Aborting.")
		return
	}

	M := make([]byte, 0)
	G_s_j_bytes, err := G_s[nTrustees-1].MarshalBinary()
	if err != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Can't marshall base, "+err.Error())
		return
	}
	M = append(M, G_s_j_bytes...)

	for j := 0; j < nClients; j++ {
		pkBytes, err := ephPublicKeys_s[nTrustees-1][j].MarshalBinary()
		if err != nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Can't marshall public key, "+err.Error())
			return
		}
		M = append(M, pkBytes...)
	}

	sig := crypto.SchnorrSign(config.CryptoSuite, rand, M, trusteeState.NodeState.PrivateKey)

	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.NodeState.Name + "; Sending signature")

	signatureMsg := make([]byte, 0)
	signatureMsg = append(signatureMsg, prifinet.IntToBA(len(sig))...)
	signatureMsg = append(signatureMsg, sig...)

	err2 := prifinet.WriteMessage(conn, signatureMsg)
	if err2 != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.NodeState.Name + "; Can't send signature, "+err2.Error())
		return
	}

	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.NodeState.Name + "; Signature sent")

	//start the handler for this round configuration
	startTrusteeSlave(trusteeState, closedConnections)

	prifilog.SimpleStringDump(prifilog.NOTIFICATION, trusteeState.NodeState.Name + "; Shutting down.")
	conn.Close()
}

func startTrusteeSlave(state *TrusteeState, closedConnections chan int) {

	incomingStream := make(chan []byte)
	//go trusteeConnRead(state, incomingStream, closedConnections)

	// Just generate ciphertext cells and stream them to the server.
	exit := false
	i := 0
	for !exit {
		select {
		case readByte := <-incomingStream:
			prifilog.Printf(prifilog.INFORMATION, "Received byte ! ", readByte)

		case connClosed := <-closedConnections:
			if connClosed == state.NodeState.Id {
				prifilog.SimpleStringDump(prifilog.INFORMATION, "Trustee "+strconv.Itoa(state.NodeState.Id)+"; Stopping handler...")
				return
			}

		default:
			// Produce a cell worth of trustee ciphertext
			tslice := state.NodeState.CellCoder.TrusteeEncode(state.NodeState.CellSize)

			// Send it to the relay
			//println("trustee slice")
			//println(hex.Dump(tslice))
			err := prifinet.WriteMessage(state.activeConnection, tslice)

			i += 1

			if i%1000000 == 0 {
				prifilog.SimpleStringDump(prifilog.NOTIFICATION, "Trustee "+strconv.Itoa(state.NodeState.Id)+"; sent up to slice "+strconv.Itoa(i)+".")
			} else if i%100000 == 0 {
				prifilog.SimpleStringDump(prifilog.INFORMATION, "Trustee "+strconv.Itoa(state.NodeState.Id)+"; sent up to slice "+strconv.Itoa(i)+".")
			}
			if err != nil {
				//fmt.Println("can't write to socket: " + err.Error())
				//fmt.Println("\nShutting down handler", state.TrusteeId, "of conn", conn.RemoteAddr())
				prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Trustee "+strconv.Itoa(state.NodeState.Id)+"; Write error, stopping handler... "+err.Error())
				exit = true
			}

		}
	}
}

func trusteeConnRead(state *TrusteeState, incomingStream chan []byte, closedConnections chan<- int) {

	for {
		// Read up to a cell worth of data to send upstream
		buf, err := prifinet.ReadMessage(state.activeConnection)

		// Connection error or EOF?
		if err == io.EOF {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Trustee "+strconv.Itoa(state.NodeState.Id)+"; Read EOF ")
		} else if err != nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Trustee "+strconv.Itoa(state.NodeState.Id)+"; Read error. "+err.Error())
			state.activeConnection.Close()
			return
		} else {
			incomingStream <- buf
		}
	}
}
