package relay

/*
PriFi Relay
************
This regroups the behavior of the PriFi relay.
Needs to be instantiated via the PriFiProtocol in prifi.go
Then, this file simple handle the answer to the different message kind :

- ALL_ALL_SHUTDOWN - kill this relay
- ALL_ALL_PARAMETERS (specialized into ALL_REL_PARAMETERS) - used to initialize the relay over the network / overwrite its configuration
- TRU_REL_TELL_PK - when a trustee connects, he tells us his public key
- CLI_REL_TELL_PK_AND_EPH_PK - when they receive the list of the trustees, each clients tells his identity. when we have all client's IDs,
								  we send them to the trustees to shuffle (Schedule protocol)
- TRU_REL_TELL_NEW_BASE_AND_EPH_PKS - when we receive the result of one shuffle, we forward it to the next trustee
- TRU_REL_SHUFFLE_SIG - when the shuffle has been done by all trustee, we send the transcript, and they answer with a signature, which we
						   broadcast to the clients
- CLI_REL_UPSTREAM_DATA - data for the DC-net
- REL_CLI_UDP_DOWNSTREAM_DATA - is NEVER received here, but casted to CLI_REL_UPSTREAM_DATA by messages.go
- TRU_REL_DC_CIPHER - data for the DC-net

local functions :

ConnectToTrustees() - simple helper
finalizeUpstreamData() - called after some Receive_CLI_REL_UPSTREAM_DATA, when we have all ciphers.
sendDownstreamData() - called after a finalizeUpstreamData(), to continue the communication
checkIfRoundHasEndedAfterTimeOut_Phase1() - called by sendDownstreamData(), which starts a new round. After some short time, if the round hasn't changed, and we used UDP,
											   retransmit messages to client over TCP
checkIfRoundHasEndedAfterTimeOut_Phase2() - called by checkIfRoundHasEndedAfterTimeOut_Phase1(). After some long time, entities that didn't send us data should be
considered disconnected

*/

import (
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"time"

	"crypto/sha256"
	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/dcnet"
	"github.com/lbarman/prifi/prifi-lib/net"
	socks "github.com/lbarman/prifi/prifi-socks"
	"github.com/lbarman/prifi/utils/timing"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
)

/*
Received_ALL_REL_SHUTDOWN handles ALL_REL_SHUTDOWN messages.
When we receive this message, we should warn other protocol participants and clean resources.
*/
func (p *PriFiLibRelayInstance) Received_ALL_ALL_SHUTDOWN(msg net.ALL_ALL_SHUTDOWN) error {
	log.Lvl1("Relay : Received a SHUTDOWN message. ")

	p.stateMachine.ChangeState("SHUTDOWN")

	msg2 := &net.ALL_ALL_SHUTDOWN{}

	var err error

	// Send this shutdown to all trustees
	for j := 0; j < p.relayState.nTrustees; j++ {
		p.messageSender.SendToTrusteeWithLog(j, msg2, "")
	}

	// Send this shutdown to all clients
	for j := 0; j < p.relayState.nClients; j++ {
		p.messageSender.SendToClientWithLog(j, msg2, "")
	}

	// TODO : stop all go-routines we created

	return err
}

/*
Received_ALL_REL_PARAMETERS handles ALL_REL_PARAMETERS.
It initializes the relay with the parameters contained in the message.
*/
func (p *PriFiLibRelayInstance) Received_ALL_ALL_PARAMETERS(msg net.ALL_ALL_PARAMETERS_NEW) error {

	startNow := msg.BoolValueOrElse("StartNow", false)
	nTrustees := msg.IntValueOrElse("NTrustees", p.relayState.nTrustees)
	nClients := msg.IntValueOrElse("NClients", p.relayState.nClients)
	upCellSize := msg.IntValueOrElse("UpstreamCellSize", p.relayState.UpstreamCellSize)
	downCellSize := msg.IntValueOrElse("DownstreamCellSize", p.relayState.DownstreamCellSize)
	windowSize := msg.IntValueOrElse("WindowSize", p.relayState.WindowSize)
	useDummyDown := msg.BoolValueOrElse("UseDummyDataDown", p.relayState.UseDummyDataDown)
	useOpenClosedSlots := msg.BoolValueOrElse("UseOpenClosedSlots", p.relayState.UseOpenClosedSlots)
	reportingLimit := msg.IntValueOrElse("ExperimentRoundLimit", p.relayState.ExperimentRoundLimit)
	useUDP := msg.BoolValueOrElse("UseUDP", p.relayState.UseUDP)
	dcNetType := msg.StringValueOrElse("DCNetType", p.relayState.dcNetType)

	p.relayState.clients = make([]NodeRepresentation, nClients)
	p.relayState.trustees = make([]NodeRepresentation, nTrustees)
	p.relayState.nClients = nClients
	p.relayState.nTrustees = nTrustees
	p.relayState.nTrusteesPkCollected = 0
	p.relayState.nClientsPkCollected = 0
	p.relayState.ExperimentRoundLimit = reportingLimit
	p.relayState.UpstreamCellSize = upCellSize
	p.relayState.DownstreamCellSize = downCellSize
	p.relayState.UseDummyDataDown = useDummyDown
	p.relayState.UseOpenClosedSlots = useOpenClosedSlots
	p.relayState.UseUDP = useUDP
	p.relayState.bufferManager.Init(nClients, nTrustees)
	p.relayState.WindowSize = windowSize
	p.relayState.numberOfNonAckedDownstreamPackets = 0
	p.relayState.MessageHistory = config.CryptoSuite.Cipher([]byte("init")) //any non-nil, non-empty, constant array
	p.relayState.VerifiableDCNetKeys = make([][]byte, nTrustees)
	p.relayState.nVkeysCollected = 0
	p.relayState.dcnetRoundManager = NewDCNetRoundManager(windowSize)
	p.relayState.dcNetType = dcNetType
	p.relayState.clientBitMap = make(map[int]map[int]int)
	p.relayState.trusteeBitMap = make(map[int]map[int]int)
	p.relayState.blamingData = make([]int, 6)

	switch dcNetType {
	case "Simple":
		p.relayState.CellCoder = dcnet.SimpleCoderFactory()
	case "Verifiable":
		p.relayState.CellCoder = dcnet.OwnedCoderFactory()
	default:
		e := "DCNetType must be Simple or Verifiable"
		log.Error(e)
		return errors.New(e)
	}

	//this should be in NewRelayState, but we need p
	if !p.relayState.bufferManager.DoSendStopResumeMessages {
		//Add rate-limiting component to buffer manager
		stopFn := func(trusteeID int) {
			toSend := &net.REL_TRU_TELL_RATE_CHANGE{WindowCapacity: 0}
			p.messageSender.SendToTrusteeWithLog(trusteeID, toSend, "(trustee "+strconv.Itoa(trusteeID)+")")
		}
		resumeFn := func(trusteeID int) {
			toSend := &net.REL_TRU_TELL_RATE_CHANGE{WindowCapacity: 1}
			p.messageSender.SendToTrusteeWithLog(trusteeID, toSend, "(trustee "+strconv.Itoa(trusteeID)+")")
		}
		p.relayState.bufferManager.AddRateLimiter(TRUSTEE_CACHE_LOWBOUND, TRUSTEE_CACHE_HIGHBOUND, stopFn, resumeFn)
	}

	log.Lvlf3("%+v\n", p.relayState)
	log.Lvl1("Relay has been initialized by message; StartNow is", startNow)

	// Broadcast those parameters to the other nodes, then tell the trustees which ID they are.
	if startNow {
		p.stateMachine.ChangeState("COLLECTING_TRUSTEES_PKS")
		p.BroadcastParameters()
	}
	log.Lvl1("Relay setup done, and setup sent to the trustees.")

	return nil
}

// ConnectToTrustees connects to the trustees and initializes them with default parameters.
func (p *PriFiLibRelayInstance) BroadcastParameters() error {

	// Craft default parameters
	msg := new(net.ALL_ALL_PARAMETERS_NEW)
	msg.Add("NClients", p.relayState.nClients)
	msg.Add("NTrustees", p.relayState.nTrustees)
	msg.Add("UseUDP", p.relayState.UseUDP)
	msg.Add("StartNow", true)
	msg.Add("UpstreamCellSize", p.relayState.UpstreamCellSize)
	msg.Add("DCNetType", p.relayState.dcNetType)
	msg.ForceParams = true

	// Send those parameters to all trustees
	for j := 0; j < p.relayState.nTrustees; j++ {

		// The ID is unique !
		msg.Add("NextFreeTrusteeID", j)
		p.messageSender.SendToTrusteeWithLog(j, msg, "")
	}

	// Send those parameters to all clients
	for j := 0; j < p.relayState.nClients; j++ {

		// The ID is unique !
		msg.Add("NextFreeClientID", j)
		p.messageSender.SendToClientWithLog(j, msg, "")
	}

	return nil
}

// Received_CLI_REL_OPENCLOSED_DATA handles the reception of the OpenClosed map, which details which
// pseudonymous clients want to transmit in a given round
func (p *PriFiLibRelayInstance) Received_CLI_REL_OPENCLOSED_DATA(msg net.CLI_REL_OPENCLOSED_DATA) error {
	p.relayState.bufferManager.SkipToRoundIfNeeded(msg.RoundID)
	p.relayState.bufferManager.AddClientCipher(msg.RoundID, msg.ClientID, msg.OpenClosedData)

	if p.relayState.bufferManager.HasAllCiphersForCurrentRound() {

		//classical DC-net decoding
		clientSlices, trusteesSlices, err := p.relayState.bufferManager.FinalizeRound()
		if err != nil {
			return err
		}
		for _, s := range clientSlices {
			p.relayState.CellCoder.DecodeClient(s)
		}
		for _, s := range trusteesSlices {
			p.relayState.CellCoder.DecodeTrustee(s)
		}

		//here we have the plaintext map
		openClosedData := p.relayState.CellCoder.DecodeCell()

		//compute the map
		sched := p.relayState.slotScheduler.Relay_ComputeFinalSchedule(openClosedData, msg.RoundID+1, p.relayState.nClients)
		p.relayState.dcnetRoundManager.SetStoredRoundSchedule(sched)

		//we finish the round
		p.doneCollectingUpstreamData(msg.RoundID)

		//one round has just passed !
		// sleep so it does not go too fast for debug
		time.Sleep(PROCESSING_LOOP_SLEEP_TIME)

		//if all slots are closed, do not immediately send the next downstream data (which will be a OCSlots schedule)
		hasOpenSlot := false
		for _, v := range sched {
			if v {
				hasOpenSlot = true
			}
		}
		if !hasOpenSlot {
			log.Lvl3("All slots closed, sleeping for", OPENCLOSEDSLOTS_MIN_DELAY_BETWEEN_REQUESTS)
			time.Sleep(OPENCLOSEDSLOTS_MIN_DELAY_BETWEEN_REQUESTS)
		}

		// send the data down
		for i := p.relayState.numberOfNonAckedDownstreamPackets; i < p.relayState.WindowSize; i++ {
			log.Lvl3("Relay : Gonna send, non-acked packets is", p.relayState.numberOfNonAckedDownstreamPackets, "(window is", p.relayState.WindowSize, ")")
			p.sendDownstreamData()
		}
	} else {
		//a, b := p.relayState.bufferManager.MissingCiphersForCurrentRound()
		//log.Error("Still missing client contribution", a, "trustee", b)
	}

	return nil
}

/*
Received_CLI_REL_UPSTREAM_DATA handles CLI_REL_UPSTREAM_DATA messages and is part of PriFi's main loop.
This is what happens in one round, for the relay. We receive some upstream data.
If we have collected data from all entities for this round, we can call DecodeCell() and get the output.
If we get data for another round (in the future) we should buffer it.
If we finished a round (we had collected all data, and called DecodeCell()), we need to finish the round by sending some data down.
Either we send something from the SOCKS/VPN buffer, or we answer the latency-test message if we received any, or we send 1 bit.
*/
func (p *PriFiLibRelayInstance) Received_CLI_REL_UPSTREAM_DATA(msg net.CLI_REL_UPSTREAM_DATA) error {
	timing.StartMeasure("dcnet-add")
	p.relayState.bufferManager.SkipToRoundIfNeeded(msg.RoundID)
	p.relayState.bufferManager.AddClientCipher(msg.RoundID, msg.ClientID, msg.Data)
	timeMs := timing.StopMeasure("dcnet-add").Nanoseconds() / 1e6
	p.relayState.timeStatistics["dcnet-add"].AddTime(timeMs)

	if p.relayState.bufferManager.HasAllCiphersForCurrentRound() {

		timeMs := timing.StopMeasure("waiting-on-someone").Nanoseconds() / 1e6
		p.relayState.timeStatistics["waiting-on-clients"].AddTime(timeMs)

		log.Lvl3("Relay has collected all ciphers for round", p.relayState.dcnetRoundManager.CurrentRound(), ", decoding...")
		p.finalizeUpstreamData()

		//one round has just passed !
		// sleep so it does not go too fast for debug
		time.Sleep(PROCESSING_LOOP_SLEEP_TIME)

		// send the data down
		for i := p.relayState.numberOfNonAckedDownstreamPackets; i < p.relayState.WindowSize; i++ {
			log.Lvl3("Relay : Gonna send, non-acked packets is", p.relayState.numberOfNonAckedDownstreamPackets, "(window is", p.relayState.WindowSize, ")")
			p.sendDownstreamData()
		}
	}

	return nil
}

/*
Received_TRU_REL_DC_CIPHER handles TRU_REL_DC_CIPHER messages. Those contain a DC-net cipher from a Trustee.
If it's for this round, we call decode on it, and remember we received it.
If for a future round we need to Buffer it.
*/
func (p *PriFiLibRelayInstance) Received_TRU_REL_DC_CIPHER(msg net.TRU_REL_DC_CIPHER) error {
	timing.StartMeasure("dcnet-add")
	p.relayState.bufferManager.AddTrusteeCipher(msg.RoundID, msg.TrusteeID, msg.Data)
	timeMs := timing.StopMeasure("dcnet-add").Nanoseconds() / 1e6
	p.relayState.timeStatistics["dcnet-add"].AddTime(timeMs)

	if p.relayState.bufferManager.HasAllCiphersForCurrentRound() {

		timeMs := timing.StopMeasure("waiting-on-someone").Nanoseconds() / 1e6
		p.relayState.timeStatistics["waiting-on-trustees"].AddTime(timeMs)

		log.Lvl3("Relay has collected all ciphers for round", p.relayState.dcnetRoundManager.CurrentRound(), ", decoding...")
		p.finalizeUpstreamData()

		// send the data down
		for i := p.relayState.numberOfNonAckedDownstreamPackets; i < p.relayState.WindowSize; i++ {
			log.Lvl3("Relay : Gonna send, non-acked packets is", p.relayState.numberOfNonAckedDownstreamPackets, "(window is", p.relayState.WindowSize, ")")
			p.sendDownstreamData()
		}
	}

	return nil
}

/*
finalizeUpstreamData is simply called when the Relay has received all ciphertexts (one per client, one per trustee),
and is ready to finalize the
DC-net round by XORing everything together.
If it's a latency-test message, we send it back to the clients.
If we use SOCKS/VPN, give them the data.
*/
func (p *PriFiLibRelayInstance) finalizeUpstreamData() error {

	p.relayState.DCNetData = nil
	// we decode the DC-net cell
	timing.StartMeasure("dcnet-decode")
	clientSlices, trusteesSlices, err := p.relayState.bufferManager.FinalizeRound()
	if err != nil {
		return err
	}

	//decode all clients and trustees
	for _, s := range clientSlices {
		p.relayState.CellCoder.DecodeClient(s)
	}
	for _, s := range trusteesSlices {
		p.relayState.CellCoder.DecodeTrustee(s)
	}
	upstreamPlaintext := p.relayState.CellCoder.DecodeCell()
	p.relayState.DCNetData = upstreamPlaintext
	p.relayState.HashRoundID = p.relayState.dcnetRoundManager.currentRound

	timeMs := timing.StopMeasure("dcnet-decode").Nanoseconds() / 1e6
	p.relayState.timeStatistics["dcnet-decode"].AddTime(timeMs)

	p.relayState.bitrateStatistics.AddUpstreamCell(int64(len(upstreamPlaintext)))

	// check if we have a latency test message
	if len(upstreamPlaintext) >= 2 {
		pattern := int(binary.BigEndian.Uint16(upstreamPlaintext[0:2]))
		if pattern == 43690 { // 1010101010101010
			// then, we simply have to send it down
			// log.Info("Relay noticed a latency-test message on round", p.relayState.dcnetRoundManager.CurrentRound())
			p.relayState.PriorityDataForClients <- upstreamPlaintext
		}
	}

	if upstreamPlaintext == nil {
		// empty upstream cell, need to finish round otherwise will enter next if clause and block protocol
		p.doneCollectingUpstreamData(p.relayState.dcnetRoundManager.CurrentRound())
		log.Lvl3("upstream is nil")
		return nil
	}

	if len(upstreamPlaintext) != p.relayState.UpstreamCellSize {
		e := "Relay : DecodeCell produced wrong-size payload, " + strconv.Itoa(len(upstreamPlaintext)) + "!=" + strconv.Itoa(p.relayState.UpstreamCellSize)
		log.Error(e)
		return errors.New(e)
	}

	timing.StartMeasure("socks-out")
	if p.relayState.DataOutputEnabled {

		packetType, _, _, _ := socks.ParseSocksHeaderFromBytes(upstreamPlaintext)

		switch packetType {
		case socks.SocksData, socks.SocksConnect, socks.StallCommunication, socks.ResumeCommunication:
			p.relayState.DataFromDCNet <- upstreamPlaintext

		default:
			break
		}

	}
	timeMs = timing.StopMeasure("socks-out").Nanoseconds() / 1e6
	p.relayState.timeStatistics["socks-out"].AddTime(timeMs)

	p.doneCollectingUpstreamData(p.relayState.dcnetRoundManager.CurrentRound())

	return nil
}

/*
sendDownstreamData is simply called when the Relay has processed the upstream cell from all clients, and is ready to finalize the round by sending the data down.
If it's a latency-test message, we send it back to the clients.
If we use SOCKS/VPN, give them the data.
Since after this function, we'll start receiving data for the next round, if we have buffered data for this next round, tell the state that we
have the data already (and we're not waiting on it). Clean the old data.
*/
func (p *PriFiLibRelayInstance) sendDownstreamData() error {

	var downstreamCellContent []byte

	select {
	case downstreamCellContent = <-p.relayState.PriorityDataForClients:
		log.Lvl3("Relay : We have some priority data for the clients")
	// TODO : maybe we can pack more than one message here ?

	default:

	}

	// only if we don't have priority data for clients
	if downstreamCellContent == nil {
		select {

		// either select data from the data we have to send, if any
		case downstreamCellContent = <-p.relayState.DataForClients:
			log.Error("Relay : We have some real data for the clients. ")

		default:
			downstreamCellContent = make([]byte, 1)
			log.Lvl3("Relay : Sending 1bit down. ")
		}
	}

	// if we want to use dummy data down, pad to the correct size
	if p.relayState.UseDummyDataDown && len(downstreamCellContent) < p.relayState.DownstreamCellSize {
		data := make([]byte, p.relayState.DownstreamCellSize)
		copy(data[0:], downstreamCellContent)
		downstreamCellContent = data
	}

	nextDownstreamRoundID := p.relayState.dcnetRoundManager.NextDownStreamRoundToSent()

	// TODO : if something went wrong before, this flag should be used to warn the clients that the config has changed
	flagResync := false

	// periodically set to True so client can advertise their bitmap
	flagOpenClosedRequest := p.relayState.UseOpenClosedSlots &&
		p.relayState.dcnetRoundManager.IsNextDownstreamRoundForOpenClosedRequest(p.relayState.nClients)

	//sending data part
	timing.StartMeasure("sending-data")
	log.Lvl3("Relay is gonna broadcast messages for round " + strconv.Itoa(int(nextDownstreamRoundID)) + ".")

	toSend := &net.REL_CLI_DOWNSTREAM_DATA{
		RoundID:               nextDownstreamRoundID,
		Data:                  downstreamCellContent,
		HashRoundID:           -1,
		Hash:                  nil,
		FlagResync:            flagResync,
		FlagOpenClosedRequest: flagOpenClosedRequest}

	if p.relayState.DCNetData != nil { //we have sent an upstream message so we broadcast the hash
		toSend.HashRoundID = p.relayState.HashRoundID
		hash := sha256.Sum256(p.relayState.DCNetData)
		toSend.Hash = hash[:]
	}

	p.relayState.dcnetRoundManager.OpenRound(nextDownstreamRoundID)
	p.relayState.dcnetRoundManager.SetDataAlreadySent(nextDownstreamRoundID, toSend)

	if !p.relayState.UseUDP {
		// broadcast to all clients
		for i := 0; i < p.relayState.nClients; i++ {
			//send to the i-th client
			p.messageSender.SendToClientWithLog(i, toSend, "(client "+strconv.Itoa(i)+", round "+strconv.Itoa(int(nextDownstreamRoundID))+")")
		}

		p.relayState.bitrateStatistics.AddDownstreamCell(int64(len(downstreamCellContent)))
	} else {
		toSend2 := &net.REL_CLI_DOWNSTREAM_DATA_UDP{REL_CLI_DOWNSTREAM_DATA: *toSend}
		p.messageSender.BroadcastToAllClientsWithLog(toSend2, "(UDP broadcast, round "+strconv.Itoa(int(nextDownstreamRoundID))+")")

		p.relayState.bitrateStatistics.AddDownstreamUDPCell(int64(len(downstreamCellContent)), p.relayState.nClients)
	}

	timeMs := timing.StopMeasure("sending-data").Nanoseconds() / 1e6
	p.relayState.timeStatistics["sending-data"].AddTime(timeMs)

	log.Lvl3("Relay is done broadcasting messages for round " + strconv.Itoa(int(nextDownstreamRoundID)) + ".")

	//we just sent the data down, initiating a round. Let's prevent being blocked by a dead client
	go p.checkIfRoundHasEndedAfterTimeOut_Phase1(nextDownstreamRoundID)

	//now relay enters a waiting state (collecting all ciphers from clients/trustees)
	timing.StartMeasure("waiting-on-someone")

	p.relayState.numberOfNonAckedDownstreamPackets++

	return nil
}

func (p *PriFiLibRelayInstance) collectExperimentResult(str string) {
	if str == "" {
		return
	}

	// if this is not an experiment, simply return
	if p.relayState.ExperimentRoundLimit == -1 {
		return
	}

	p.relayState.ExperimentResultData = append(p.relayState.ExperimentResultData, str)
}

func (p *PriFiLibRelayInstance) doneCollectingUpstreamData(roundID int32) error {

	timing.StartMeasure("round-transition")
	p.relayState.numberOfNonAckedDownstreamPackets--

	if roundID == 0 {
		log.Lvl2("Relay finished round " + strconv.Itoa(int(roundID)) + " .")
	} else {
		log.Lvl2("Relay finished round "+strconv.Itoa(int(roundID))+" (after", p.relayState.dcnetRoundManager.TimeSpentInRound(roundID), ").")
		p.collectExperimentResult(p.relayState.bitrateStatistics.Report())
		timeSpent := p.relayState.dcnetRoundManager.TimeSpentInRound(roundID)
		p.relayState.timeStatistics["round-duration"].AddTime(timeSpent.Nanoseconds() / 1e6) //ms
		for k, v := range p.relayState.timeStatistics {
			p.collectExperimentResult(v.ReportWithInfo(k))
		}
	}

	// Test if we are doing an experiment, and if we need to stop at some point.
	newRound := p.relayState.dcnetRoundManager.CurrentRound()
	if newRound == int32(p.relayState.ExperimentRoundLimit) {
		log.Lvl1("Relay : Experiment round limit (", newRound, ") reached")
		p.relayState.ExperimentResultChannel <- p.relayState.ExperimentResultData

		// shut down everybody
		msg := net.ALL_ALL_SHUTDOWN{}
		p.Received_ALL_ALL_SHUTDOWN(msg)
	}
	//prepare for the next round
	p.relayState.dcnetRoundManager.CloseRound(roundID)
	p.relayState.CellCoder.DecodeStart(p.relayState.UpstreamCellSize, p.relayState.MessageHistory) //this empties the buffer, making them ready for a new round

	timeMs := timing.StopMeasure("round-transition").Nanoseconds() / 1e6
	p.relayState.timeStatistics["round-transition"].AddTime(timeMs)
	return nil
}

/*
Received_TRU_REL_TELL_PK handles TRU_REL_TELL_PK messages. Those are sent by the trustees message when we connect them.
We do nothing, until we have received one per trustee; Then, we pack them in one message, and broadcast it to the clients.
*/
func (p *PriFiLibRelayInstance) Received_TRU_REL_TELL_PK(msg net.TRU_REL_TELL_PK) error {

	p.relayState.trustees[msg.TrusteeID] = NodeRepresentation{msg.TrusteeID, true, msg.Pk, msg.Pk}
	p.relayState.nTrusteesPkCollected++

	log.Lvl2("Relay : received TRU_REL_TELL_PK (" + strconv.Itoa(p.relayState.nTrusteesPkCollected) + "/" + strconv.Itoa(p.relayState.nTrustees) + ")")

	// if we have them all...
	if p.relayState.nTrusteesPkCollected == p.relayState.nTrustees {

		// prepare the message for the clients
		trusteesPk := make([]abstract.Point, p.relayState.nTrustees)
		for i := 0; i < p.relayState.nTrustees; i++ {
			trusteesPk[i] = p.relayState.trustees[i].PublicKey
		}

		// Send the pack to the clients
		toSend := &net.REL_CLI_TELL_TRUSTEES_PK{Pks: trusteesPk}
		for i := 0; i < p.relayState.nClients; i++ {
			p.messageSender.SendToClientWithLog(i, toSend, "(client "+strconv.Itoa(i)+")")
		}

		p.stateMachine.ChangeState("COLLECTING_CLIENT_PKS")
	}
	return nil
}

/*
Received_CLI_REL_TELL_PK_AND_EPH_PK handles CLI_REL_TELL_PK_AND_EPH_PK messages.
Those are sent by the client to tell their identity.
We do nothing until we have collected one per client; then, we pack them in one message
and send them to the first trustee for it to Neff-Shuffle them.
*/
func (p *PriFiLibRelayInstance) Received_CLI_REL_TELL_PK_AND_EPH_PK(msg net.CLI_REL_TELL_PK_AND_EPH_PK) error {

	p.relayState.clients[msg.ClientID] = NodeRepresentation{msg.ClientID, true, msg.Pk, msg.EphPk}
	p.relayState.nClientsPkCollected++

	log.Lvl2("Relay : received CLI_REL_TELL_PK_AND_EPH_PK (" + strconv.Itoa(p.relayState.nClientsPkCollected) + "/" + strconv.Itoa(p.relayState.nClients) + ")")

	// if we have collected all clients, continue
	if p.relayState.nClientsPkCollected == p.relayState.nClients {

		p.relayState.neffShuffle.Init(p.relayState.nTrustees)

		for i := 0; i < p.relayState.nClients; i++ {
			p.relayState.neffShuffle.AddClient(p.relayState.clients[i].EphemeralPublicKey)
		}

		msg, trusteeID, err := p.relayState.neffShuffle.SendToNextTrustee()
		if err != nil {
			e := "Could not do p.relayState.neffShuffle.SendToNextTrustee, error is " + err.Error()
			log.Error(e)
			return errors.New(e)
		}
		toSend := msg.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)

		//todo: fix this. The neff shuffle now stores twices the ephemeral public keys
		toSend.Pks = make([]abstract.Point, p.relayState.nClients)
		for i := 0; i < p.relayState.nClients; i++ {
			toSend.Pks[i] = p.relayState.clients[i].PublicKey
		}

		// send to the 1st trustee
		p.messageSender.SendToTrusteeWithLog(trusteeID, toSend, "(0-th iteration)")

		p.stateMachine.ChangeState("COLLECTING_SHUFFLES")

		timing.StopMeasure("Resync")
	}

	return nil
}

/*
Received_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS handles TRU_REL_TELL_NEW_BASE_AND_EPH_PKS messages.
Those are sent by the trustees once they finished a Neff-Shuffle.
In that case, we forward the result to the next trustee.
We do nothing until the last trustee sends us this message.
When this happens, we pack a transcript, and broadcast it to all the trustees who will sign it.
*/
func (p *PriFiLibRelayInstance) Received_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS(msg net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS) error {

	p.relayState.VerifiableDCNetKeys[p.relayState.nVkeysCollected] = msg.VerifiableDCNetKey
	p.relayState.nVkeysCollected++

	done, err := p.relayState.neffShuffle.ReceivedShuffleFromTrustee(msg.NewBase, msg.NewEphPks, msg.Proof)
	if err != nil {
		e := "Relay : error in p.relayState.neffShuffle.ReceivedShuffleFromTrustee " + err.Error()
		log.Error(e)
		return errors.New(e)
	}

	// if we're still waiting on some trustees, send them the new shuffle
	if !done {

		msg, trusteeID, err := p.relayState.neffShuffle.SendToNextTrustee()
		if err != nil {
			e := "Could not do p.relayState.neffShuffle.SendToNextTrustee, error is " + err.Error()
			log.Error(e)
			return errors.New(e)
		}
		toSend := msg.(*net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)

		//todo: fix this. The neff shuffle now stores twices the ephemeral public keys
		toSend.Pks = make([]abstract.Point, p.relayState.nClients)
		for i := 0; i < p.relayState.nClients; i++ {
			toSend.Pks[i] = p.relayState.clients[i].PublicKey
		}

		// send to the i-th trustee
		p.messageSender.SendToTrusteeWithLog(trusteeID, toSend, "("+strconv.Itoa(trusteeID)+"-th iteration)")

	} else {
		// if we have all the shuffles

		msg, err := p.relayState.neffShuffle.SendTranscript()
		if err != nil {
			e := "Could not do p.relayState.neffShuffle.SendTranscript(), error is " + err.Error()
			log.Error(e)
			return errors.New(e)
		}

		toSend := msg.(*net.REL_TRU_TELL_TRANSCRIPT)

		// broadcast to all trustees
		for j := 0; j < p.relayState.nTrustees; j++ {
			// send to the j-th trustee
			p.messageSender.SendToTrusteeWithLog(j, toSend, "(trustee "+strconv.Itoa(j+1)+")")
		}

		p.relayState.CellCoder.RelaySetup(config.CryptoSuite, p.relayState.VerifiableDCNetKeys)

		// prepare to collect the ciphers
		p.relayState.CellCoder.DecodeStart(p.relayState.UpstreamCellSize, p.relayState.MessageHistory)

		p.stateMachine.ChangeState("COLLECTING_SHUFFLE_SIGNATURES")

	}

	return nil
}

/*
Received_TRU_REL_SHUFFLE_SIG handles TRU_REL_SHUFFLE_SIG messages.
Those contain the signature from the NeffShuffleS-transcript from one trustee.
We do nothing until we have all signatures; when we do, we pack those
in one message with the result of the Neff-Shuffle and send them to the clients.
When this is done, we are finally ready to communicate. We wait for the client's messages.
*/
func (p *PriFiLibRelayInstance) Received_TRU_REL_SHUFFLE_SIG(msg net.TRU_REL_SHUFFLE_SIG) error {

	done, err := p.relayState.neffShuffle.ReceivedSignatureFromTrustee(msg.TrusteeID, msg.Sig)
	if err != nil {
		e := "Could not do p.relayState.neffShuffle.ReceivedSignatureFromTrustee(), error is " + err.Error()
		log.Error(e)
		return errors.New(e)
	}

	// if we have all the signatures
	if done {
		trusteesPks := make([]abstract.Point, p.relayState.nTrustees)
		i := 0
		for _, v := range p.relayState.trustees {
			trusteesPks[i] = v.PublicKey
			i++
		}

		toSend5, err := p.relayState.neffShuffle.VerifySigsAndSendToClients(trusteesPks)
		if err != nil {
			e := "Could not do p.relayState.neffShuffle.VerifySigsAndSendToClients(), error is " + err.Error()
			log.Error(e)
			return errors.New(e)
		}
		msg := toSend5.(*net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)
		// changing state
		log.Lvl2("Relay : ready to communicate.")
		p.stateMachine.ChangeState("COMMUNICATING")

		// broadcast to all clients
		for i := 0; i < p.relayState.nClients; i++ {
			// send to the i-th client
			p.messageSender.SendToClientWithLog(i, msg, "(client "+strconv.Itoa(i+1)+")")
		}

		//client will answer will CLI_REL_UPSTREAM_DATA. There is no data down on round 0. We set the following variable to 1 since the reception of CLI_REL_UPSTREAM_DATA decrements it.
		p.relayState.numberOfNonAckedDownstreamPackets = 1
	}

	return nil
}

/*
Received_CLI_REL_QUERY handles CLI_REL_QUERY messages.
When we receive it we check the NIZK (not yet).
If correct we send back the corrupted plaintext message encrypted with the received public key.
*/
func (p *PriFiLibRelayInstance) Received_CLI_REL_QUERY(msg net.CLI_REL_QUERY) error {

	//Check NIZK

	encryptedMessage, dataLeft := config.CryptoSuite.Point().Pick(p.relayState.DCNetData, config.CryptoSuite.Cipher([]byte("encryption")))
	if dataLeft != nil {
		log.Lvl2("Message could not entirely be embedded in the point") //todo what to do then ?
	}
	encryptedMessage.Add(encryptedMessage, msg.Pk)
	toSend := &net.REL_CLI_QUERY{
		RoundID:       msg.RoundID,
		EncryptedData: encryptedMessage}

	// broadcast to all clients
	for i := 0; i < p.relayState.nClients; i++ {
		// send to the i-th client
		p.messageSender.SendToClientWithLog(i, toSend, "(client "+strconv.Itoa(i+1)+")")
	}

	return nil
}

/*
Received_CLI_REL_BLAME handles CLI_REL_BLAME messages.
When we receive it we check the NIZK (not yet).
If correct we stop communication (after ending current round) and ask all users to reveal bits.
*/
func (p *PriFiLibRelayInstance) Received_CLI_REL_BLAME(msg net.CLI_REL_BLAME) error {

	//Check NIZK
	p.stateMachine.ChangeState("BLAMING")

	toSend := &net.REL_ALL_REVEAL{
		RoundID: msg.RoundID,
		BitPos:  msg.BitPos}

	p.relayState.blamingData[0] = int(msg.RoundID)
	p.relayState.blamingData[1] = msg.BitPos

	// broadcast to all trustees
	for j := 0; j < p.relayState.nTrustees; j++ {
		// send to the j-th trustee
		p.messageSender.SendToTrusteeWithLog(j, toSend, "Reveal message sent to trustee "+strconv.Itoa(j+1))
	}

	// broadcast to all clients
	for i := 0; i < p.relayState.nClients; i++ {
		// send to the i-th client
		p.messageSender.SendToClientWithLog(i, toSend, "Reveal message sent to client "+strconv.Itoa(i+1))
	}

	//Bool var to let the round finish then stop, switch to state blaming, and reveal ?

	return nil
}

/*
Received_CLI_REL_REVEAL handles CLI_REL_REVEAL messages
Put bits in maps and find the disruptor if we received everything
*/
func (p *PriFiLibRelayInstance) Received_CLI_REL_REVEAL(msg net.CLI_REL_REVEAL) error {

	p.relayState.clientBitMap[msg.ClientID] = msg.Bits

	if (len(p.relayState.clientBitMap) == p.relayState.nClients) && (len(p.relayState.trusteeBitMap) == p.relayState.nTrustees) {
		p.findDisruptor()
	}
	return nil
}

/*
Received_TRU_REL_REVEAL handles TRU_REL_REVEAL messages
Put bits in maps and find the disruptor if we received everything
*/
func (p *PriFiLibRelayInstance) Received_TRU_REL_REVEAL(msg net.TRU_REL_REVEAL) error {

	p.relayState.trusteeBitMap[msg.TrusteeID] = msg.Bits

	if (len(p.relayState.clientBitMap) == p.relayState.nClients) && (len(p.relayState.trusteeBitMap) == p.relayState.nTrustees) {
		p.findDisruptor()
	}
	return nil
}

/*
findDisruptor is called when we received all the bits from clients and trustees, we must find a mismatch
*/
func (p *PriFiLibRelayInstance) findDisruptor() error {

	for clientID, val := range p.relayState.clientBitMap {
		for trusteeID, values := range p.relayState.trusteeBitMap {
			if val[trusteeID] != values[clientID] {
				log.Lvl1("Found difference between client ", clientID, " and trustee ", trusteeID)

				// message to trustee j and client i to reveal secrets
				p.relayState.blamingData[2] = clientID
				p.relayState.blamingData[3] = val[trusteeID]
				p.relayState.blamingData[4] = trusteeID
				p.relayState.blamingData[5] = values[clientID]
				toSend := &net.REL_ALL_SECRET{
					UserID: clientID}
				p.messageSender.SendToTrustee(trusteeID, toSend)
				toSend2 := &net.REL_ALL_SECRET{
					UserID: trusteeID}
				p.messageSender.SendToClient(clientID, toSend2)
				return nil
			}
		}
	}
	log.Lvl1("Found no differences in revealed bits")
	return nil
}

/*
Received_TRU_REL_SECRET handles TRU_REL_SECRET messages
Check the NIZK, if correct regenerate the cipher up to the disrupted round and check if this trustee is the disruptor
*/
func (p *PriFiLibRelayInstance) Received_TRU_REL_SECRET(msg net.TRU_REL_SECRET) error {
	val := p.replayRounds(msg.Secret)
	if val != p.relayState.blamingData[5] {
		log.Lvl1("Trustee ", p.relayState.blamingData[4], " lied and is considered a disruptor")
	}
	return nil
}

/*
Received_CLI_REL_SECRET handles CLI_REL_SECRET messages
Check the NIZK, if correct regenerate the cipher up to the disrupted round and check if this client is the disruptor
*/
func (p *PriFiLibRelayInstance) Received_CLI_REL_SECRET(msg net.CLI_REL_SECRET) error {
	val := p.replayRounds(msg.Secret)
	if val != p.relayState.blamingData[3] {
		log.Lvl1("Client ", p.relayState.blamingData[2], " lied and is considered a disruptor")
	}
	return nil
}

/*
replayRounds takes the secret revealed by a user and recomputes until the disrupted bit
*/
func (p *PriFiLibRelayInstance) replayRounds(secret abstract.Point) int {
	bytes, err := secret.MarshalBinary()
	if err != nil {
		log.Fatal("Could not marshal point !")
	}
	roundID := p.relayState.blamingData[0]
	sharedPRNG := config.CryptoSuite.Cipher(bytes)
	key := make([]byte, config.CryptoSuite.Cipher(nil).KeySize())
	sharedPRNG.Partial(key, key, nil)
	dcCipher := config.CryptoSuite.Cipher(key)

	for i := 0; i < roundID; i++ {
		//discard crypto material
		dst := make([]byte, p.relayState.UpstreamCellSize)
		dcCipher.Read(dst)
	}

	dst := make([]byte, p.relayState.UpstreamCellSize)
	dcCipher.Read(dst)
	bitPos := p.relayState.blamingData[0]
	m := float64(bitPos) / float64(8)
	m = math.Floor(m)
	m2 := int(m)
	n := bitPos % 8
	mask := byte(1 << uint8(n))
	if (dst[m2] & mask) == 0 {
		return 0
	}
	return 1
}
