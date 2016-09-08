package trustee

import (
	"bytes"
	"encoding/binary"
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
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Error reading public keys "+err.Error())
		return
	}

	// Create a shared secret with every client
	trusteeState.SharedSecrets = make([]abstract.Cipher, len(clientsPublicKeys))
	for i := 0; i < len(clientsPublicKeys); i++ {
		trusteeState.ClientPublicKeys[i] = clientsPublicKeys[i]
		sharedPoint := config.CryptoSuite.Point().Mul(clientsPublicKeys[i], trusteeState.PrivateKey)
		sharedBytes, _ := sharedPoint.MarshalBinary()
		trusteeState.SharedSecrets[i] = config.CryptoSuite.Cipher(sharedBytes)
	}

	// Check that we got all client public keys
	for i := 0; i < nClients; i++ {
		if trusteeState.ClientPublicKeys[i] == nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Didn't get public keys from client "+strconv.Itoa(i))
			return
		}
	}

	// Parse the ephemeral keys
	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.Name + "; All crypto stuff exchanged ! ")
	base, ephPublicKeys, err := prifinet.ParseBaseAndPublicKeysFromConn(conn)

	if err != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Error parsing ephemeral keys, quitting. "+err.Error())
		return
	}

	// Perform round shuffling
	roundShuffling(trusteeState, conn, base, ephPublicKeys)

	// Initialize the cell coder
	vkeyBytes := trusteeState.CellCoder.TrusteeSetup(config.CryptoSuite, trusteeState.SharedSecrets)

	// Send my composite verifable shared secret to the relay
	if err := prifinet.WriteMessage(conn, vkeyBytes); err != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "Cannot write to the relay. " + err.Error())
	}

	// Start the main message loop
	startMessageLoop(trusteeState, closedConnections)

	prifilog.SimpleStringDump(prifilog.NOTIFICATION, trusteeState.Name + "; Shutting down.")
	conn.Close()
}

func roundShuffling(trusteeState *TrusteeState, conn net.Conn,
	base abstract.Point, ephPublicKeys []abstract.Point) {

	var err error
	nClients := trusteeState.NumClients
	nTrustees := trusteeState.NumTrustees

	rand := config.CryptoSuite.Cipher([]byte(trusteeState.Name))
	H := trusteeState.PublicKey
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

	// Send back the shuffle
	prifinet.WriteBasePublicKeysAndProofToConn(conn, base2, ephPublicKeys2, proof)
	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.Name + "; Shuffling done, wrote back to the relay ")

	// Wait, verify, and sign the transcript
	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.Name + "; Parsing the transcript ...")

	G_s, ephPublicKeys_s, proof_s, err := prifinet.ParseTranscript(conn, nClients, nTrustees)

	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.Name + "; Verifying the transcript... ")

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
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Transcript invalid for trustee "+strconv.Itoa(j)+". Aborting.")
			return
		}
	}

	// Verify that my shuffle was included
	ownPermutationFound := false
	for j := 0; j < nTrustees; j++ {

		if G_s[j].Equal(base2) && bytes.Equal(proof, proof_s[j]) {
			prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.Name + "; Find in transcript : Found indice "+strconv.Itoa(j)+" that seems to match, verifing all the keys...")
			allKeyEqual := true
			for k := 0; k < nClients; k++ {
				if !ephPublicKeys2[k].Equal(ephPublicKeys_s[j][k]) {
					prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Transcript invalid for trustee "+strconv.Itoa(j)+". Aborting.")
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
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Can't find own transaction. Aborting.")
		return
	}

	M := make([]byte, 0)
	G_s_j_bytes, err := G_s[nTrustees-1].MarshalBinary()
	if err != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Can't marshall base, "+err.Error())
		return
	}
	M = append(M, G_s_j_bytes...)

	for j := 0; j < nClients; j++ {
		pkBytes, err := ephPublicKeys_s[nTrustees-1][j].MarshalBinary()
		if err != nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Can't marshall public key, "+err.Error())
			return
		}
		M = append(M, pkBytes...)
	}

	sig := crypto.SchnorrSign(config.CryptoSuite, rand, M, trusteeState.PrivateKey)

	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.Name + "; Sending signature")

	signatureMsg := make([]byte, 0)
	signatureMsg = append(signatureMsg, prifinet.IntToBA(len(sig))...)
	signatureMsg = append(signatureMsg, sig...)

	err2 := prifinet.WriteMessage(conn, signatureMsg)
	if err2 != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, trusteeState.Name + "; Can't send signature, "+err2.Error())
		return
	}

	prifilog.SimpleStringDump(prifilog.INFORMATION, trusteeState.Name + "; Signature sent")
}

func startMessageLoop(state *TrusteeState, closedConnections chan int) {

	incomingStream := make(chan []byte)
	//go trusteeConnRead(state, incomingStream, closedConnections)

	// Just generate ciphertext cells and stream them to the relay
	exit := false
	i := 0
	for !exit {
		select {
		case readByte := <-incomingStream:
			prifilog.Printf(prifilog.INFORMATION, "Received byte ! ", readByte)

		case connClosed := <-closedConnections:
			if connClosed == state.Id {
				prifilog.SimpleStringDump(prifilog.INFORMATION, "Trustee "+strconv.Itoa(state.Id)+"; Stopping handler...")
				return
			}

		default:
			// Produce a cell worth of trustee ciphertext
			tslice := state.CellCoder.TrusteeEncode(state.CellSize)

			// Send it to the relay
			err := prifinet.WriteMessage(state.activeConnection, tslice)

			i += 1

			if i%1000000 == 0 {
				prifilog.SimpleStringDump(prifilog.NOTIFICATION, "Trustee "+strconv.Itoa(state.Id)+"; sent up to slice "+strconv.Itoa(i)+".")
			} else if i%100000 == 0 {
				prifilog.SimpleStringDump(prifilog.INFORMATION, "Trustee "+strconv.Itoa(state.Id)+"; sent up to slice "+strconv.Itoa(i)+".")
			}
			if err != nil {
				prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Trustee "+strconv.Itoa(state.Id)+"; Write error, stopping handler... "+err.Error())
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
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Trustee "+strconv.Itoa(state.Id)+"; Read EOF ")
		} else if err != nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Trustee "+strconv.Itoa(state.Id)+"; Read error. "+err.Error())
			state.activeConnection.Close()
			return
		} else {
			incomingStream <- buf
		}
	}
}
