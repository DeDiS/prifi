package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/lbarman/prifi/auth"
	"github.com/lbarman/prifi/config"
	"github.com/lbarman/prifi/crypto"
	prifilog "github.com/lbarman/prifi/log"
	prifinet "github.com/lbarman/prifi/net"
	"github.com/lbarman/prifi/node"
	"os"
)

func StartClient(nodeConfig config.NodeConfig, relayHostAddr string, expectedNumberOfClients int, nTrustees int,
	payloadLength int, useSocksProxy bool, latencyTest bool, useUDP bool) {

	prifilog.SimpleStringDump(prifilog.NOTIFICATION, "Client "+strconv.Itoa(nodeConfig.Id)+" started...")

	clientState := new(ClientState)
	clientState.NodeState = node.InitNodeState(nodeConfig, expectedNumberOfClients, nTrustees, payloadLength)

	clientState.UseSocksProxy = useSocksProxy
	clientState.LatencyTest = latencyTest
	clientState.UseUDP = useUDP
	clientState.TrusteePublicKey = make([]abstract.Point, nTrustees)

	stats := prifilog.EmptyStatistics(-1) //no limit

	// Connect to relay
	relayTCPConn, relayUDPConn, err := connectToRelay(relayHostAddr, clientState)

	// Define downstream stream (relay -> client)
	dataFromRelay := make(chan prifinet.DataWithMessageTypeAndConnId)

	// Start the socks proxy
	socksProxyNewConnections := make(chan net.Conn)
	dataForRelayBuffer := make(chan []byte, 0)                               // This will hold the data to be sent later on to the relay, anonymized
	dataForSocksProxy := make(chan prifinet.DataWithMessageTypeAndConnId, 0) // This hold the data from the relay to one of the SOCKS connection

	if clientState.UseSocksProxy {
		port := ":" + strconv.Itoa(1080+nodeConfig.Id)
		prifilog.SimpleStringDump(prifilog.INFORMATION, "Client "+strconv.Itoa(nodeConfig.Id)+"; Starting SOCKS proxy on port "+port)
		go startSocksProxyServerListener(port, socksProxyNewConnections)
		go startSocksProxyServerHandler(socksProxyNewConnections, dataForRelayBuffer, dataForSocksProxy, clientState)
	}

	exitClient := false
	authenticated := false

	for !exitClient {

		if relayTCPConn == nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(nodeConfig.Id)+"; trying to configure, but relay not connected. connecting...")
			relayTCPConn, relayUDPConn, err = connectToRelay(relayHostAddr, clientState)

			if err != nil {

				prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(nodeConfig.Id)+"; Could not TCP connect to the relay, restarting")
				relayTCPConn.Close()
				relayTCPConn = nil

				if relayUDPConn != nil {
					relayUDPConn.Close()
					relayUDPConn = nil
				}

				continue //redo everything
			}
		}

		if !authenticated {
			// Authenticate the client via the relay
			err := auth.ClientAuthentication(nodeConfig.AuthMethod, relayTCPConn, clientState.Id, clientState.PrivateKey)
			if err != nil {
				// TODO: Client authentication failed. Retry a few times.
				prifilog.SimpleStringDump(prifilog.SEVERE_ERROR, "Authentication failed.")
				os.Exit(1)
			}
			authenticated = true
		}

		prifilog.SimpleStringDump(prifilog.INFORMATION, "Client "+strconv.Itoa(nodeConfig.Id)+"; Waiting for relay params + public keys...")
		params, err := readPublicKeysFromRelay(relayTCPConn, clientState)
		prifilog.SimpleStringDump(prifilog.INFORMATION, "Client "+strconv.Itoa(nodeConfig.Id)+"; Got the parameters from relay")

		if err != nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(nodeConfig.Id)+"; Could not get the parameters from the relay, restarting")
			relayTCPConn.Close()
			relayTCPConn = nil

			if relayUDPConn != nil {
				relayUDPConn.Close()
				relayUDPConn = nil
			}
			continue //redo everything
		}
		clientState.NodeState.NumClients = params.nClients

		// Parse trustee's public keys
		clientState.NodeState.NumTrustees = len(params.trusteesPublicKeys)
		clientState.TrusteePublicKey = make([]abstract.Point, clientState.NodeState.NumTrustees)

		// Create a shared secret with every trustee
		clientState.NodeState.SharedSecrets = make([]abstract.Cipher, len(params.trusteesPublicKeys))
		for i := 0; i < len(params.trusteesPublicKeys); i++ {
			clientState.TrusteePublicKey[i] = params.trusteesPublicKeys[i]
			sharedPoint := config.CryptoSuite.Point().Mul(params.trusteesPublicKeys[i], clientState.NodeState.PrivateKey)
			sharedBytes, _ := sharedPoint.MarshalBinary()
			clientState.NodeState.SharedSecrets[i] = config.CryptoSuite.Cipher(sharedBytes)
		}

		//check that we got all keys
		for i := 0; i < clientState.NodeState.NumTrustees; i++ {
			if clientState.TrusteePublicKey[i] == nil {
				prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(nodeConfig.Id)+"; Didn't get public key from trustee "+strconv.Itoa(i)+", restarting")
				relayTCPConn.Close()
				relayTCPConn = nil
				continue //redo everything
			}
		}

		// Initialize cell coder
		clientState.CellCoder.ClientSetup(config.CryptoSuite, clientState.NodeState.SharedSecrets)
		clientState.UsablePayloadLength = clientState.NodeState.CellCoder.ClientCellSize(payloadLength)

		//TODO: Shuffle to detect if we own the slot
		myRound, err := roundScheduling(relayTCPConn, clientState)

		if err != nil {
			relayTCPConn.Close()
			relayTCPConn = nil
			continue //redo everything
		}

		//clientState.printSecrets()
		prifilog.SimpleStringDump(prifilog.NOTIFICATION, "Client "+strconv.Itoa(nodeConfig.Id)+"; Everything ready, assigned to round "+
			strconv.Itoa(myRound)+" out of "+strconv.Itoa(clientState.NodeState.NumClients))

		//define downstream stream (relay -> client)
		stopReadRelay := make(chan bool, 1)
		relayDisconnected := make(chan bool, 1)
		go readDataFromRelay(relayTCPConn, relayUDPConn, dataFromRelay, stopReadRelay, relayDisconnected, clientState)

		roundCount := 0
		continueToNextRound := true
		for continueToNextRound {
			select {

			case d := <-relayDisconnected:
				if d {
					prifilog.SimpleStringDump(prifilog.WARNING, "Client "+strconv.Itoa(nodeConfig.Id)+"; Connection to relay lost, reconfigurating...")
					continueToNextRound = false
				}

			//downstream slice from relay (normal DC-net cycle)
			case data := <-dataFromRelay:

				//compute in which round we are (respective to the number of Clients)
				currentRound := roundCount % clientState.NodeState.NumClients
				isMySlot := false
				if currentRound == myRound {
					isMySlot = true
				}

				switch data.MessageType {

				case prifinet.MESSAGE_TYPE_LAST_UPLOAD_FAILED:
					//relay wants to re-setup (new key exchanges)
					prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(nodeConfig.Id)+"; Relay warns that a client disconnected, gonna resync..")
					continueToNextRound = false

				case prifinet.MESSAGE_TYPE_DATA_AND_RESYNC:
					//relay wants to re-setup (new key exchanges)
					prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(nodeConfig.Id)+"; Relay wants to resync...")
					continueToNextRound = false

				case prifinet.MESSAGE_TYPE_DATA:

					//test if it is the answer from a ping
					if len(data.Data) > 2 {
						pattern := int(binary.BigEndian.Uint16(data.Data[0:2]))

						if pattern == 43690 { //1010101010101010
							clientId := int(binary.BigEndian.Uint16(data.Data[2:4]))

							if clientId == clientState.Id {

								timestamp := int64(binary.BigEndian.Uint64(data.Data[4:12]))
								diff := prifilog.MsTimeStamp() - timestamp

								//prifilog.Println(prifilog.EXPERIMENT_OUTPUT, "Client "+strconv.Itoa(nodeConfig.Id) +"; Latency is ", fmt.Sprintf("%v", diff) + "ms")

								stats.AddLatency(diff)
							}
						} else {
							prifilog.Println(prifilog.SEVERE_ERROR, "Unexpected downstream message received. Something is wrong...")
						}
					} else {
						//data for SOCKS proxy, just hand it over to the dedicated thread
						if clientState.UseSocksProxy {
							dataForSocksProxy <- data
						}
					}
					stats.AddDownstreamCell(int64(len(data.Data)))
				}

				// Update the downstream history
				s := config.CryptoSuite.Scalar().Pick(clientState.DownstreamHistory)
				histBytes,_ := s.MarshalBinary()
				newHist := make([]byte, len(histBytes) + len(data.Data))
				copy(newHist[:len(histBytes)], histBytes)
				copy(newHist[len(histBytes):], data.Data)
				clientState.DownstreamHistory = config.CryptoSuite.Cipher(newHist)

				// Produce and ship the next upstream slice
				nBytes := writeNextUpstreamSlice(isMySlot, dataForRelayBuffer, relayTCPConn, clientState)
				if nBytes == -1 {
					//couldn't write anything, relay is disconnected
					relayTCPConn = nil
					continueToNextRound = false
				}
				stats.AddUpstreamCell(int64(nBytes))

				//we report the speed, bytes exchanged, etc
				stats.ReportWithInfo(fmt.Sprintf("cellsize=%v ", payloadLength))
			}
			roundCount++
		}
	}
}

func roundScheduling(relayTCPConn net.Conn, clientState *ClientState) (int, error) {

	prifilog.SimpleStringDump(prifilog.INFORMATION, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Generating ephemeral keys...")
	clientState.NodeState.GenerateEphemeralKeys()

	// Tell the relay our ephemeral public key
	ephPublicKeyBytes, _ := clientState.NodeState.EphemeralPublicKey.MarshalBinary()
	keySize := len(ephPublicKeyBytes)

	buffer := make([]byte, 2+keySize)
	binary.BigEndian.PutUint16(buffer[0:2], uint16(prifinet.MESSAGE_TYPE_PUBLICKEYS))
	copy(buffer[2:], ephPublicKeyBytes)

	err := prifinet.WriteMessage(relayTCPConn, buffer)
	if err != nil {
		prifilog.SimpleStringDump(prifilog.SEVERE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Error writing ephemeral key "+err.Error())
		return -1, err
	}

	prifilog.SimpleStringDump(prifilog.INFORMATION, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; waiting for the trustees signatures ")

	G, ephPubKeys, signatures, err := prifinet.ParseBasePublicKeysAndTrusteeSignaturesFromConn(relayTCPConn)

	if err != nil {
		return -1, err
	}

	// Composing the signed message
	G_bytes, _ := G.MarshalBinary()
	M := make([]byte, 0)
	M = append(M, G_bytes...)
	for k := 0; k < len(ephPubKeys); k++ {
		pkBytes, _ := ephPubKeys[k].MarshalBinary()
		M = append(M, pkBytes...)
	}

	// Verifying the signature for all trustees
	for j := 0; j < clientState.NodeState.NumTrustees; j++ {
		err := crypto.SchnorrVerify(config.CryptoSuite, M, clientState.TrusteePublicKey[j], signatures[j])

		if err != nil {
			prifilog.SimpleStringDump(prifilog.SEVERE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; signature from trustee "+strconv.Itoa(j)+" is invalid")
			return -1, err
		}
	}
	prifilog.SimpleStringDump(prifilog.INFORMATION, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; all signatures Ok")

	// Identify which slot we own
	myPrivKey := clientState.NodeState.EphemeralPrivateKey
	ephPubInBaseG := config.CryptoSuite.Point().Mul(G, myPrivKey)
	mySlot := -1

	for j := 0; j < len(ephPubKeys); j++ {
		if ephPubKeys[j].Equal(ephPubInBaseG) {
			mySlot = j
			break
		}
	}

	if mySlot == -1 {
		prifilog.SimpleStringDump(prifilog.SEVERE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Can't recognize our slot !")
		return -1, errors.New("We don't have a slot !")
	}

	return mySlot, nil
}

/*
 * Creates the next cell
 */

func writeNextUpstreamSlice(isMySlot bool, dataForRelayBuffer chan []byte, relayTCPConn net.Conn, clientState *ClientState) int {
	var nextUpstreamBytes []byte

	if isMySlot {
		select {
		case nextUpstreamBytes = <-dataForRelayBuffer:

		default:
			if clientState.LatencyTest {

				if clientState.NodeState.CellSize < 12 {
					panic("Trying to do a Latency test, but payload is smaller than 10 bytes.")
				}

				buffer := make([]byte, clientState.NodeState.CellSize)
				pattern := uint16(43690)           //1010101010101010
				currTime := prifilog.MsTimeStamp() //timestamp in Ms

				binary.BigEndian.PutUint16(buffer[0:2], pattern)
				binary.BigEndian.PutUint16(buffer[2:4], uint16(clientState.NodeState.Id))
				binary.BigEndian.PutUint64(buffer[4:12], uint64(currTime))

				nextUpstreamBytes = buffer
			}
		}
	}

	// Produce the next upstream cell
	upstreamSlice := clientState.NodeState.CellCoder.ClientEncode(nextUpstreamBytes,
		clientState.NodeState.CellSize, clientState.NodeState.DownstreamHistory)

	if len(upstreamSlice) != clientState.UsablePayloadLength {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Client slice wrong size, expected "+strconv.Itoa(clientState.UsablePayloadLength)+", but got "+strconv.Itoa(len(upstreamSlice)))
		return -1 //relay probably disconnected
	}

	err := prifinet.WriteMessage(relayTCPConn, upstreamSlice)

	if err != nil {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Client write to relay error, err : "+err.Error())
		return -1 //relay probably disconnected
	}

	return len(upstreamSlice)
}

/*
 * RELAY CONNECTION
 */

func connectToRelay(relayHost string, clientState *ClientState) (net.Conn, net.Conn, error) {

	var tcpConn net.Conn = nil
	var udpConn net.Conn = nil
	var err error = nil

	// Connect via TCP
	for tcpConn == nil {
		tcpConn, err = net.Dial("tcp", relayHost)
		if err != nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Can't TCP connect to relay on "+relayHost+", gonna retry")
			tcpConn = nil
			time.Sleep(FAILED_CONNECTION_WAIT_BEFORE_RETRY)
		}
	}

	if !clientState.UseUDP {
		prifilog.SimpleStringDump(prifilog.INFORMATION, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Skipping UDP connection.")
	} else {
		// Connect via UDP
		startIndex := strings.LastIndex(relayHost, ":") + 1
		localPort := ":" + relayHost[startIndex:] //remove localhost

		for udpConn == nil {
			addr, err := net.ResolveUDPAddr("udp4", localPort)

			if err != nil {
				prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Can't resolve UDP address "+localPort+", gonna retry")
				time.Sleep(FAILED_CONNECTION_WAIT_BEFORE_RETRY)
				continue
			}

			udpConn, err = net.ListenUDP("udp4", addr)
			if err != nil {
				prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Can't listen on UDP on "+addr.String()+", gonna retry")
				udpConn = nil
				time.Sleep(FAILED_CONNECTION_WAIT_BEFORE_RETRY)
			}
		}
		prifilog.Println(prifilog.INFORMATION, "Listening on UDP addr "+localPort)
	}
	return tcpConn, udpConn, nil
}

func readPublicKeysFromRelay(relayTCPConn net.Conn, clientState *ClientState) (ParamsFromRelay, error) {

	// Read the next (downstream) header from the relay
	message, err := prifinet.ReadMessage(relayTCPConn)

	if err != nil {
		return ParamsFromRelay{}, errors.New("readPublicKeysFromRelay: " + err.Error())
	}

	//parse the header
	messageType := int(binary.BigEndian.Uint16(message[0:2]))
	nClients := int(binary.BigEndian.Uint32(message[2:6]))
	data := message[6:]

	if messageType != prifinet.MESSAGE_TYPE_PUBLICKEYS {
		prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Expected message type "+strconv.Itoa(prifinet.MESSAGE_TYPE_PUBLICKEYS)+", got "+strconv.Itoa(messageType))
		return ParamsFromRelay{}, errors.New("Expecting params from relay, got another message")
	}

	publicKeys, err := prifinet.UnMarshalPublicKeyArrayFromByteArray(data, config.CryptoSuite)
	if err != nil {
		prifilog.SimpleStringDump(prifilog.SEVERE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; Could not unmarshall the keys")
		return ParamsFromRelay{}, err
	}

	params := ParamsFromRelay{publicKeys, nClients}
	return params, nil
}

func readDataFromRelay(relayTCPConn net.Conn, relayUDPConn net.Conn, dataFromRelay chan<- prifinet.DataWithMessageTypeAndConnId,
	stopReadRelay chan bool, relayDisconnected chan bool, clientState *ClientState) {

	for {
		// Read the next (downstream) header from the relay
		message, err := prifinet.ReadMessage(relayTCPConn)

		if err != nil {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; ClientReadRelay error, relay probably disconnected, stopping goroutine")
			relayDisconnected <- true
			return
		}

		//switch : if it's 8 bytes, it indicates the size of a message of UDP
		if relayUDPConn != nil && len(message) == 8 {

			udpMessageExpectedSeq := uint32(binary.BigEndian.Uint32(message[0:4]))
			udpMessageLength := int(binary.BigEndian.Uint32(message[4:8]))
			udpMessageSeq := uint32(0)

			//prifilog.Println(prifilog.RECOVERABLE_ERROR, "Expecting packet " + strconv.Itoa(int(udpMessageExpectedSeq)) + " size "+strconv.Itoa(int(udpMessageLength)))

			udpMessage, err2 := prifinet.ReadDatagramWithTimeOut(relayUDPConn, udpMessageLength, UDP_DATAGRAM_WAIT_TIMEOUT)

			if err2 == nil && len(udpMessage) >= 4 {
				udpMessageSeq = uint32(binary.BigEndian.Uint32(udpMessage[0:4]))

				//prifilog.Println(prifilog.RECOVERABLE_ERROR, "Got one packet with seq " + strconv.Itoa(int(udpMessageSeq)) + " size " + strconv.Itoa(len(udpMessage)))

				//if we're behind, quickly read the rest
				for udpMessageSeq != udpMessageExpectedSeq {

					prifilog.Println(prifilog.RECOVERABLE_ERROR, "I'm behind, expected UDP segment "+strconv.Itoa(int(udpMessageExpectedSeq))+", just got "+strconv.Itoa(int(udpMessageSeq)))
					udpMessage, err2 = prifinet.ReadDatagramWithTimeOut(relayUDPConn, udpMessageLength, UDP_DATAGRAM_WAIT_TIMEOUT/10)

					if err2 == nil && len(udpMessage) >= 4 {
						udpMessageSeq = uint32(binary.BigEndian.Uint32(udpMessage[0:4]))
					} else {

						prifilog.Println(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; ClientReadRelay UDP warning, error receiving second message, giving up. gonna send NACK and read over TCP")

						//empty UDP buffer
						m, _ := prifinet.ReadDatagramWithTimeOut(relayUDPConn, 1, UDP_DATAGRAM_WAIT_TIMEOUT/10)
						for m != nil {
							m, _ = prifinet.ReadDatagramWithTimeOut(relayUDPConn, 1, UDP_DATAGRAM_WAIT_TIMEOUT/10)
						}

						break
					}
				}
			}

			//here, the seq number if correct
			ack := make([]byte, 1)
			if len(udpMessage) == udpMessageLength && err2 == nil && udpMessageExpectedSeq == udpMessageSeq {
				//send ACK
				ack[0] = 1
				prifinet.WriteMessage(relayTCPConn, ack)

				//prifilog.Println(prifilog.RECOVERABLE_ERROR, "Well received UDP packet "+strconv.Itoa(int(udpMessageSeq))+", wrote ACK back")
				message = udpMessage[4:]
			} else {
				//send NACK
				ack[0] = 0
				if err2 != nil {
					prifilog.Println(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; ClientReadRelay UDP warning, received", len(udpMessage), "instead of advertised", udpMessageLength, "bytes, err is", err2.Error(), " gonna send NACK and read over TCP")
				} else if udpMessageExpectedSeq != udpMessageSeq {
					prifilog.Println(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; ClientReadRelay UDP warning, received seq ", udpMessageSeq, "instead of advertised seq", udpMessageExpectedSeq, ". gonna send NACK and read over TCP")
				} else {
					prifilog.Println(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; ClientReadRelay UDP warning, received", len(udpMessage), "instead of advertised", udpMessageLength, "bytes, gonna send NACK read over TCP")
				}
				prifinet.WriteMessage(relayTCPConn, ack)
				messageRetransmittedOverTCP, err := prifinet.ReadMessage(relayTCPConn)

				if err != nil {
					prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+"; ClientReadRelay error (over retransmitted TCP message), relay probably disconnected, stopping goroutine")
					relayDisconnected <- true
					return
				}

				message = messageRetransmittedOverTCP
			}
		}

		//parse the header
		messageType := int(binary.BigEndian.Uint16(message[0:2]))
		socksConnId := int(binary.BigEndian.Uint32(message[2:6]))
		data := message[6:]

		//communicate to main thread
		dataFromRelay <- prifinet.DataWithMessageTypeAndConnId{messageType, socksConnId, data}

		if messageType == prifinet.MESSAGE_TYPE_DATA_AND_RESYNC || messageType == prifinet.MESSAGE_TYPE_LAST_UPLOAD_FAILED {
			prifilog.SimpleStringDump(prifilog.RECOVERABLE_ERROR, "Client "+strconv.Itoa(clientState.NodeState.Id)+" next message is gonna be some parameters, not data. Stop this goroutine")
			return
		}
	}
}

/*
 * SOCKS PROXY
 */

func startSocksProxyServerListener(port string, newConnections chan<- net.Conn) {
	prifilog.SimpleStringDump(prifilog.NOTIFICATION, "Listening on port "+port)

	lsock, err := net.Listen("tcp", port)

	if err != nil {
		prifilog.Printf(prifilog.RECOVERABLE_ERROR, "Can't open listen socket at port %s: %s", port, err.Error())
		return
	}

	for {
		conn, err := lsock.Accept()
		prifilog.Printf(prifilog.INFORMATION, "Accept on port %s\n", port)

		if err != nil {
			lsock.Close()
			return
		}
		newConnections <- conn
	}
}

func startSocksProxyServerHandler(socksProxyNewConnections chan net.Conn, dataForRelayBuffer chan []byte, dataForSOCKSProxy chan prifinet.DataWithMessageTypeAndConnId, clientState *ClientState) {

	socksProxyActiveConnections := make([]net.Conn, 1) // reserve socksProxyActiveConnections[0]
	socksProxyConnClosed := make(chan int)
	socksProxyData := make(chan []byte)

	for {
		select {

		// New TCP connection to the SOCKS proxy
		case conn := <-socksProxyNewConnections:
			newSocksProxyId := len(socksProxyActiveConnections)
			socksProxyActiveConnections = append(socksProxyActiveConnections, conn)
			go readDataFromSocksProxy(newSocksProxyId, clientState.NodeState.CellSize, conn, socksProxyData, socksProxyConnClosed)

		// Data to anonymize from SOCKS proxy
		case data := <-socksProxyData:
			dataForRelayBuffer <- data

		// Plaintext downstream data (relay->client->Socks proxy)
		case dataTypeConn := <-dataForSOCKSProxy:
			messageType := dataTypeConn.MessageType //we know it's data for relay
			socksConnId := dataTypeConn.ConnectionId
			data := dataTypeConn.Data
			dataLength := len(data)

			prifilog.Printf(prifilog.INFORMATION, "Read a message with type", messageType, " socks id ", socksConnId)

			//Handle the connections, forwards the downstream slice to the SOCKS proxy
			//if there is no socks proxy, nothing to do (useless case indeed, only for debug)
			if clientState.UseSocksProxy {
				if dataLength > 0 && socksProxyActiveConnections[socksConnId] != nil {
					n, err := socksProxyActiveConnections[socksConnId].Write(data)
					if n < dataLength {
						prifilog.Printf(prifilog.RECOVERABLE_ERROR, "Write to socks proxy: expected "+strconv.Itoa(dataLength)+" bytes, got "+strconv.Itoa(n)+", "+err.Error())
					}
				} else {
					// Relay indicating EOF on this conn
					prifilog.Printf(prifilog.RECOVERABLE_ERROR, "Relay to client : closed socks conn %d", socksConnId)
					socksProxyActiveConnections[socksConnId].Close()
				}
			}

		//connection closed from SOCKS proxy
		case socksConnId := <-socksProxyConnClosed:
			socksProxyActiveConnections[socksConnId] = nil
		}
	}
}

func readDataFromSocksProxy(socksConnId int, payloadLength int, conn net.Conn, data chan<- []byte, closed chan<- int) {
	for {
		// Read up to a cell worth of data to send upstream
		buffer := make([]byte, payloadLength)
		n, err := conn.Read(buffer[socksHeaderLength:])

		// Encode the connection number and actual data length
		binary.BigEndian.PutUint32(buffer[0:4], uint32(socksConnId))
		binary.BigEndian.PutUint16(buffer[4:6], uint16(n))

		data <- buffer

		// Connection error or EOF?
		if n == 0 {
			if err == io.EOF {
				prifilog.Printf(prifilog.RECOVERABLE_ERROR, "clientUpload: EOF, closing")
			} else {
				prifilog.Printf(prifilog.RECOVERABLE_ERROR, "clientUpload: "+err.Error())
			}
			conn.Close()
			closed <- socksConnId // signal that channel is closed
			return
		}
	}
}
