package client

/**
 * PriFi Client
 * ************
 * This regroups the behavior of the PriFi client.
 * Needs to be instantiated via the PriFiProtocol in prifi.go
 * Then, this file simple handle the answer to the different message kind :
 *
 * - ALL_ALL_SHUTDOWN - kill this client
 * - ALL_ALL_PARAMETERS (specialized into ALL_CLI_PARAMETERS) - used to initialize the client over the network / overwrite its configuration
 * - REL_CLI_TELL_TRUSTEES_PK - the trustee's identities. We react by sending our identity + ephemeral identity
 * - REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG - the shuffle from the trustees. We do some check, if they pass, we can communicate. We send the first round to the relay.
 * - REL_CLI_DOWNSTREAM_DATA - the data from the relay, for one round. We react by finishing the round (sending our data to the relay)
 *
 * local functions :
 *
 *
 * ProcessDownStreamData() <- is called by Received_REL_CLI_DOWNSTREAM_DATA; it handles the raw data received
 * SendUpstreamData() <- it is called at the end of ProcessDownStreamData(). Hence, after getting some data down, we send some data up.
 *
 * TODO : traffic need to be encrypted
 */

import (
	"errors"
	"strconv"

	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/crypto"
	prifilog "github.com/lbarman/prifi/prifi-lib/log"
	"github.com/lbarman/prifi/prifi-lib/net"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"

	"github.com/lbarman/prifi/prifi-lib/dcnet"
	"github.com/lbarman/prifi/prifi-lib/scheduler"
	"github.com/lbarman/prifi/prifi-lib/utils"
	socks "github.com/lbarman/prifi/prifi-socks"
	"github.com/lbarman/prifi/utils/timing"
	"math/rand"
	"time"
)

// Received_ALL_CLI_SHUTDOWN handles ALL_CLI_SHUTDOWN messages.
// When we receive this message, we should clean up resources.
func (p *PriFiLibClientInstance) Received_ALL_ALL_SHUTDOWN(msg net.ALL_ALL_SHUTDOWN) error {
	log.Lvl2("Client " + strconv.Itoa(p.clientState.ID) + " : Received a SHUTDOWN message. ")

	p.stateMachine.ChangeState("SHUTDOWN")

	return nil
}

// Received_ALL_CLI_PARAMETERS handles ALL_CLI_PARAMETERS messages.
// It uses the message's parameters to initialize the client.
func (p *PriFiLibClientInstance) Received_ALL_ALL_PARAMETERS(msg net.ALL_ALL_PARAMETERS_NEW) error {

	clientID := msg.IntValueOrElse("NextFreeClientID", -1)
	nTrustees := msg.IntValueOrElse("NTrustees", p.clientState.nTrustees)
	nClients := msg.IntValueOrElse("NClients", p.clientState.nClients)
	upCellSize := msg.IntValueOrElse("UpstreamCellSize", p.clientState.PayloadLength) //todo: change this name
	useUDP := msg.BoolValueOrElse("UseUDP", p.clientState.UseUDP)
	dcNetType := msg.StringValueOrElse("DCNetType", "not initialized")

	//sanity checks
	if clientID < -1 {
		return errors.New("ClientID cannot be negative")
	}
	if nTrustees < 1 {
		return errors.New("nTrustees cannot be smaller than 1")
	}
	if nClients < 1 {
		return errors.New("nClients cannot be smaller than 1")
	}
	if upCellSize < 1 {
		return errors.New("UpCellSize cannot be 0")
	}

	switch dcNetType {
	case "Simple":
		p.clientState.DCNet_FF.CellCoder = dcnet.SimpleCoderFactory()
	case "Verifiable":
		p.clientState.DCNet_FF.CellCoder = dcnet.OwnedCoderFactory()
	default:
		log.Fatal("DCNetType must be Simple or Verifiable")
	}

	//set the received parameters
	p.clientState.ID = clientID
	p.clientState.Name = "Client-" + strconv.Itoa(clientID)
	p.clientState.MySlot = -1
	p.clientState.nClients = nClients
	p.clientState.nTrustees = nTrustees
	p.clientState.PayloadLength = upCellSize
	p.clientState.UsablePayloadLength = p.clientState.DCNet_FF.CellCoder.ClientCellSize(upCellSize)
	p.clientState.UseUDP = useUDP
	p.clientState.TrusteePublicKey = make([]abstract.Point, nTrustees)
	p.clientState.sharedSecrets = make([]abstract.Point, nTrustees)
	p.clientState.RoundNo = int32(0)
	p.clientState.BufferedRoundData = make(map[int32]net.REL_CLI_DOWNSTREAM_DATA)
	p.clientState.MessageHistory = config.CryptoSuite.Cipher([]byte("init")) //any non-nil, non-empty, constant array

	//we know our client number, if needed, parse the pcap for replay
	if p.clientState.pcapReplay.Enabled {
		p.clientState.pcapReplay.PCAPFile = p.clientState.pcapReplay.PCAPFolder + "client" + strconv.Itoa(clientID) + ".pcap"
		packets, err := utils.ParsePCAP(p.clientState.pcapReplay.PCAPFile)
		if err != nil {
			log.Error("Requested PCAP Replay, but could not parse; Error is", err)
		}
		p.clientState.pcapReplay.Packets = packets
		log.Lvl1("Client", clientID, "loaded corresponding PCAP with", len(packets), "packets.")
	}

	//if by chance we had a broadcast-listener goroutine, kill it
	if p.clientState.StartStopReceiveBroadcast != nil {
		p.clientState.StartStopReceiveBroadcast <- false
	}
	p.clientState.StartStopReceiveBroadcast = make(chan bool, 10)

	//start the broadcast-listener goroutine
	if useUDP {
		go p.messageSender.MessageSender.ClientSubscribeToBroadcast(p.clientState.ID, p.ReceivedMessage, p.clientState.StartStopReceiveBroadcast)
	}

	//after receiving this message, we are done with the state CLIENT_STATE_BEFORE_INIT, and are ready for initializing
	p.stateMachine.ChangeState("INITIALIZING")

	log.Lvl2("Client " + strconv.Itoa(p.clientState.ID) + " has been initialized by message. ")

	return nil
}

/*
Received_REL_CLI_DOWNSTREAM_DATA handles REL_CLI_DOWNSTREAM_DATA messages which are part of PriFi's main loop.
This is what happens in one round, for this client. We receive some downstream data.
It should be encrypted, and we should test if this data is for us or not; if so, push it into the SOCKS/VPN chanel.
For now, we do nothing with the downstream data.
Once we received some data from the relay, we need to reply with a DC-net cell (that will get combined with other client's cell to produce some plaintext).
If we're lucky (if this is our slot), we are allowed to embed some message (which will be the output produced by the relay). Either we send something from the
SOCKS/VPN data, or if we're running latency tests, we send a "ping" message to compute the latency. If we have nothing to say, we send 0's.
*/
func (p *PriFiLibClientInstance) Received_REL_CLI_DOWNSTREAM_DATA(msg net.REL_CLI_DOWNSTREAM_DATA) error {

	//check if it is in-order
	if msg.RoundID == p.clientState.RoundNo {
		//process downstream data
		return p.ProcessDownStreamData(msg)
	} else if msg.RoundID < p.clientState.RoundNo {
		log.Lvl3("Client " + strconv.Itoa(p.clientState.ID) + " : Received a REL_CLI_DOWNSTREAM_DATA for round " + strconv.Itoa(int(msg.RoundID)) + " but we are in round " + strconv.Itoa(int(p.clientState.RoundNo)) + ", discarding.")
	} else if msg.RoundID > p.clientState.RoundNo {
		log.Lvl3("Client "+strconv.Itoa(p.clientState.ID)+" : Skipping from round", p.clientState.RoundNo, "to round", msg.RoundID)
		p.clientState.RoundNo = msg.RoundID
		return p.ProcessDownStreamData(msg)
		//this is not used anymore, with the Open/Closed slot schedule
		//log.Lvl3("Client " + strconv.Itoa(p.clientState.ID) + " : Received a REL_CLI_DOWNSTREAM_DATA for round " + strconv.Itoa(int(msg.RoundID)) + " but we are in round " + strconv.Itoa(int(p.clientState.RoundNo)) + ", buffering.")
		//p.clientState.BufferedRoundData[msg.RoundID] = msg
	}

	return nil
}

/*
Received_REL_CLI_UDP_DOWNSTREAM_DATA handles REL_CLI_UDP_DOWNSTREAM_DATA messages which are part of PriFi's main loop.
This is what happens in one round, for this client.
We receive some downstream data. It should be encrypted, and we should test if this data is for us or not; is so, push it into the SOCKS/VPN chanel.
For now, we do nothing with the downstream data.
Once we received some data from the relay, we need to reply with a DC-net cell (that will get combined with other client's cell to produce some plaintext).
If we're lucky (if this is our slot), we are allowed to embed some message (which will be the output produced by the relay). Either we send something from the
SOCKS/VPN data, or if we're running latency tests, we send a "ping" message to compute the latency. If we have nothing to say, we send 0's.
*/
func (p *PriFiLibClientInstance) Received_REL_CLI_UDP_DOWNSTREAM_DATA(msg net.REL_CLI_DOWNSTREAM_DATA_UDP) error {

	return p.Received_REL_CLI_DOWNSTREAM_DATA(msg.REL_CLI_DOWNSTREAM_DATA)
}

/*
ProcessDownStreamData handles the downstream data. After determining if the data is for us (this is not done yet), we test if it's a
latency-test message, test if the resync flag is on (which triggers a re-setup).
When this function ends, it calls SendUpstreamData() which continues the communication loop.
*/
func (p *PriFiLibClientInstance) ProcessDownStreamData(msg net.REL_CLI_DOWNSTREAM_DATA) error {

	timing.StartMeasure("round-processing")

	/*
	 * HANDLE THE DOWNSTREAM DATA
	 */

	//if it's just one byte, no data
	if len(msg.Data) > 1 {

		//pass the data to the VPN/SOCKS5 proxy, if enabled
		if p.clientState.DataOutputEnabled {
			p.clientState.DataFromDCNet <- msg.Data
		}
		//test if it is the answer from our ping (for latency test)
		if p.clientState.LatencyTest.DoLatencyTests && len(msg.Data) > 2 {

			actionFunction := func(roundRec int32, roundDiff int32, timeDiff int64) {
				log.Info("Measured latency is", timeDiff, ", for client", p.clientState.ID, ", roundDiff", roundDiff, ", received on round", msg.RoundID)
				p.clientState.timeStatistics["measured-latency"].AddTime(timeDiff)
				p.clientState.timeStatistics["measured-latency"].ReportWithInfo("measured-latency")
			}
			prifilog.DecodeLatencyMessages(msg.Data, p.clientState.ID, msg.RoundID, actionFunction)
		}
	}

	//if the flag "Resync" is on, we cannot write data up, but need to resend the keys instead
	if msg.FlagResync == true {

		log.Lvl1("Client " + strconv.Itoa(p.clientState.ID) + " : Relay wants to resync, going to state CLIENT_STATE_INITIALIZING ")
		p.stateMachine.ChangeState("INITIALIZING")

		//TODO : regenerate ephemeral keys ?

		return nil

		//if the flag FlagOpenClosedRequest
	} else if msg.FlagOpenClosedRequest == true {

		log.Lvl2("Client " + strconv.Itoa(p.clientState.ID) + " : Relay wants to open/closed schedule slots ")

		//do the schedule
		bmc := new(scheduler.BitMaskSlotScheduler_Client)
		bmc.Client_ReceivedScheduleRequest(p.clientState.RoundNo+1, p.clientState.nClients)

		//since this round nobody sends, move "MySlot" for everybody
		p.clientState.MySlot = (p.clientState.MySlot + 1) % p.clientState.nClients

		//find the slot that will be ours in the next round
		i := p.clientState.RoundNo + 1
		for i%int32(p.clientState.nClients) != int32(p.clientState.MySlot) {
			i++
		}
		mySlotInNextRound := int32(i)

		//check if we want to transmit
		if p.WantsToTransmit() {
			log.Lvl3("Client "+strconv.Itoa(p.clientState.ID)+" : Gonna reserve round", mySlotInNextRound)
			bmc.Client_ReserveRound(mySlotInNextRound)
		}
		contribution := bmc.Client_GetOpenScheduleContribution()

		//produce the next upstream cell
		upstreamCell := p.clientState.DCNet_FF.ClientEncodeForRound(p.clientState.RoundNo, contribution, p.clientState.PayloadLength, p.clientState.MessageHistory)

		//send the data to the relay
		toSend := &net.CLI_REL_OPENCLOSED_DATA{
			ClientID:       p.clientState.ID,
			RoundID:        p.clientState.RoundNo,
			OpenClosedData: upstreamCell}
		p.messageSender.SendToRelayWithLog(toSend, "(round "+strconv.Itoa(int(p.clientState.RoundNo))+")")

	} else {
		//send upstream data for next round
		p.SendUpstreamData()
	}

	//test if we have latency test to send
	now := time.Now()
	if p.clientState.LatencyTest.DoLatencyTests && now.After(p.clientState.LatencyTest.NextLatencyTest) {
		newLatTest := &prifilog.LatencyTestToSend{
			CreatedAt: now,
		}
		p.clientState.LatencyTest.LatencyTestsToSend = append(p.clientState.LatencyTest.LatencyTestsToSend, newLatTest)
		p.clientState.LatencyTest.NextLatencyTest = now.Add(p.clientState.LatencyTest.LatencyTestsInterval)
		p.clientState.LatencyTest.NextLatencyTest = p.clientState.LatencyTest.NextLatencyTest.Add(time.Duration(rand.Intn(1000)) * time.Millisecond)
	}

	//clean old buffered messages
	delete(p.clientState.BufferedRoundData, int32(p.clientState.RoundNo-1))

	//one round just passed
	p.clientState.RoundNo++

	//now we will be expecting next message. Except if we already received and buffered it !
	if msg, hasAMessage := p.clientState.BufferedRoundData[int32(p.clientState.RoundNo)]; hasAMessage {
		p.Received_REL_CLI_DOWNSTREAM_DATA(msg)
	}

	timeMs := timing.StopMeasure("round-processing").Nanoseconds() / 1e6
	p.clientState.timeStatistics["round-processing"].AddTime(timeMs)
	p.clientState.timeStatistics["round-processing"].ReportWithInfo("round-processing")

	return nil
}

// WantsToTransmit returns true if [we have a latency message to send] OR [we have data to send]
func (p *PriFiLibClientInstance) WantsToTransmit() bool {

	//if we have a latency test message
	if len(p.clientState.LatencyTest.LatencyTestsToSend) > 0 {
		return true
	}

	//if we have already ready-to-send data
	if p.clientState.NextDataForDCNet != nil {
		return true
	}

	//otherwise, poll the channel
	select {
	case myData := <-p.clientState.DataForDCNet:
		p.clientState.NextDataForDCNet = &myData
		return true

	default:
		return false
	}
}

/*
SendUpstreamData determines if it's our round, embeds data (maybe latency-test message) in the payload if we can,
creates the DC-net cipher and sends it to the relay.
*/
func (p *PriFiLibClientInstance) SendUpstreamData() error {
	//TODO: maybe make this into a method func (p *PrifiProtocol) isMySlot() bool {}
	//write the next upstream slice. First, determine if we can embed payload this round
	currentRound := p.clientState.RoundNo % int32(p.clientState.nClients)
	isMySlot := false
	if currentRound == int32(p.clientState.MySlot) {
		isMySlot = true
	}

	var upstreamCellContent []byte

	//if we can...
	if isMySlot {
		//this data has already been polled out of the DataForDCNet chan, so send it first
		//this is non-nil when OpenClosedSlot is true, and that it had to poll data out
		if p.clientState.NextDataForDCNet != nil {
			upstreamCellContent = *p.clientState.NextDataForDCNet
			p.clientState.NextDataForDCNet = nil
		} else {
			select {

			//either select data from the data we have to send, if any
			case myData := <-p.clientState.DataForDCNet:
				upstreamCellContent = myData

			//or, if we have nothing to send, and we are doing Latency tests, embed a pre-crafted message that we will recognize later on
			default:
				emptyData := socks.NewSocksPacket(socks.DummyData, 0, 0, uint16(p.clientState.PayloadLength), make([]byte, 0))
				upstreamCellContent = emptyData.ToBytes()

				if len(p.clientState.LatencyTest.LatencyTestsToSend) > 0 {

					logFn := func(timeDiff int64) {
						p.clientState.timeStatistics["latency-msg-stayed-in-buffer"].AddTime(timeDiff)
						p.clientState.timeStatistics["latency-msg-stayed-in-buffer"].ReportWithInfo("latency-msg-stayed-in-buffer")
					}

					bytes, outMsgs := prifilog.LatencyMessagesToBytes(p.clientState.LatencyTest.LatencyTestsToSend,
						p.clientState.ID, p.clientState.RoundNo, p.clientState.PayloadLength, logFn)

					p.clientState.LatencyTest.LatencyTestsToSend = outMsgs
					upstreamCellContent = bytes
				}
			}
		}
	}

	//produce the next upstream cell
	upstreamCell := p.clientState.DCNet_FF.ClientEncodeForRound(p.clientState.RoundNo, upstreamCellContent, p.clientState.PayloadLength, p.clientState.MessageHistory)
	//send the data to the relay
	toSend := &net.CLI_REL_UPSTREAM_DATA{
		ClientID: p.clientState.ID,
		RoundID:  p.clientState.RoundNo,
		Data:     upstreamCell}
	p.messageSender.SendToRelayWithLog(toSend, "(round "+strconv.Itoa(int(p.clientState.RoundNo))+")")

	return nil
}

/*
Received_REL_CLI_TELL_TRUSTEES_PK handles REL_CLI_TELL_TRUSTEES_PK messages. These are sent when we connect.
The relay sends us a pack of public key which correspond to the set of pre-agreed trustees.
Of course, there should be check on those public keys (each client need to trust one), but for now we assume those public keys belong indeed to the trustees,
and that clients have agreed on the set of trustees.
Once we receive this message, we need to reply with our Public Key (Used to derive DC-net secrets), and our Ephemeral Public Key (used for the Shuffle protocol)
*/
func (p *PriFiLibClientInstance) Received_REL_CLI_TELL_TRUSTEES_PK(msg net.REL_CLI_TELL_TRUSTEES_PK) error {

	//sanity check
	if len(msg.Pks) < 1 {
		e := "Client " + strconv.Itoa(p.clientState.ID) + " : len(msg.Pks) must be >= 1"
		log.Error(e)
		return errors.New(e)
	}

	p.clientState.TrusteePublicKey = make([]abstract.Point, p.clientState.nTrustees)
	p.clientState.sharedSecrets = make([]abstract.Point, p.clientState.nTrustees)

	for i := 0; i < len(msg.Pks); i++ {
		p.clientState.TrusteePublicKey[i] = msg.Pks[i]
		p.clientState.sharedSecrets[i] = config.CryptoSuite.Point().Mul(msg.Pks[i], p.clientState.privateKey)
	}

	//set up the DC-nets
	sharedPRNGs := make([]abstract.Cipher, p.clientState.nTrustees)
	for i := 0; i < p.clientState.nTrustees; i++ {
		bytes, err := p.clientState.sharedSecrets[i].MarshalBinary()
		if err != nil {
			return errors.New("Could not marshal point !")
		}
		sharedPRNGs[i] = config.CryptoSuite.Cipher(bytes)
	}
	p.clientState.DCNet_FF.CellCoder.ClientSetup(config.CryptoSuite, sharedPRNGs)

	//then, generate our ephemeral keys (used for shuffling)
	p.clientState.EphemeralPublicKey, p.clientState.ephemeralPrivateKey = crypto.NewKeyPair()

	//send the keys to the relay
	toSend := &net.CLI_REL_TELL_PK_AND_EPH_PK{
		ClientID: p.clientState.ID,
		Pk:       p.clientState.PublicKey,
		EphPk:    p.clientState.EphemeralPublicKey,
	}
	p.messageSender.SendToRelayWithLog(toSend, "")

	p.stateMachine.ChangeState("EPH_KEYS_SENT")

	return nil
}

/*
Received_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG handles REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG messages.
These are sent after the Shuffle protocol has been done by the Trustees and the Relay.
The relay is sending us the result, so we should check that the protocol went well :
1) each trustee announced must have signed the shuffle
2) we need to locate which is our slot
When this is done, we are ready to communicate !
As the client should send the first data, we do so; to keep this function simple, the first data is blank
(the message has no content / this is a wasted message). The actual embedding of data happens only in the
"round function", that is Received_REL_CLI_DOWNSTREAM_DATA().
*/
func (p *PriFiLibClientInstance) Received_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG(msg net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG) error {

	//verify the signature
	neff := new(scheduler.NeffShuffle)
	mySlot, err := neff.ClientVerifySigAndRecognizeSlot(p.clientState.ephemeralPrivateKey, p.clientState.TrusteePublicKey, msg.Base, msg.EphPks, msg.GetSignatures())

	if err != nil {
		e := "Client " + strconv.Itoa(p.clientState.ID) + "; Can't recognize our slot ! err is " + err.Error()
		log.Error(e)
	}

	//prepare for commmunication
	p.clientState.MySlot = mySlot
	p.clientState.RoundNo = int32(0)
	p.clientState.BufferedRoundData = make(map[int32]net.REL_CLI_DOWNSTREAM_DATA)

	//if by chance we had a broadcast-listener goroutine, kill it
	if p.clientState.UseUDP {
		if p.clientState.StartStopReceiveBroadcast == nil {
			e := "Client " + strconv.Itoa(p.clientState.ID) + " wish to start listening with UDP, but doesn't have the appropriate helper."
			log.Error(e)
			return errors.New(e)
		}
		p.clientState.StartStopReceiveBroadcast <- true
		log.Lvl3("Client " + strconv.Itoa(p.clientState.ID) + " indicated the udp-helper to start listening.")
	}

	//change state
	p.stateMachine.ChangeState("READY")
	log.Lvl3("Client " + strconv.Itoa(p.clientState.ID) + " is ready to communicate.")

	//produce a blank cell (we could embed data, but let's keep the code simple, one wasted message is not much)
	upstreamCell := p.clientState.DCNet_FF.ClientEncodeForRound(0, nil, p.clientState.PayloadLength, p.clientState.MessageHistory)

	//send the data to the relay
	toSend := &net.CLI_REL_UPSTREAM_DATA{
		ClientID: p.clientState.ID,
		RoundID:  p.clientState.RoundNo,
		Data:     upstreamCell,
	}
	p.messageSender.SendToRelayWithLog(toSend, "(round "+strconv.Itoa(int(p.clientState.RoundNo))+")")

	p.clientState.RoundNo++

	return nil
}
