package relay

import (
	"github.com/dedis/prifi/prifi-lib/net"
	"go.dedis.ch/onet/log"
	"strconv"
	"time"
)

/*
This first timeout happens after a short delay. Clients will not be considered disconnected yet,
but if we use UDP, it can mean that a client missed a broadcast, and we re-sent the message.
If the round was *not* done, we do another timeout (Phase 2), and then, clients/trustees will be considered
online if they didn't answer by that time.
*/
func (p *PriFiLibRelayInstance) checkIfRoundHasEndedAfterTimeOut_Phase1(roundID int32) {

	time.Sleep(time.Duration(p.relayState.RoundTimeOut) * time.Millisecond)

	// never start treating two timeout concurrently (or receiving a message)
	p.relayState.processingLock.Lock()
	defer p.relayState.processingLock.Unlock()

	if !p.relayState.roundManager.IsRoundOpenend(roundID) {
		return //everything went well, it's great !
	}

	if p.stateMachine.State() == "SHUTDOWN" {
		return //nothing to ensure in that case
	}

	// new policy : just kill that round, do not retransmit, let SOCKS take care of the loss

	p.relayState.numberOfConsecutiveFailedRounds++
	log.Lvl1("WARNING: Timeout for round", roundID, ", force closing. Already", p.relayState.numberOfConsecutiveFailedRounds,
		"consecutive missed rounds (killing when =>", p.relayState.MaxNumberOfConsecutiveFailedRounds, ")")

	// if we missed too many rounds, kill the experiment
	missingClientCiphers, missingTrusteeCiphers := p.relayState.roundManager.MissingCiphersForCurrentRound()
	log.Lvl1("missing clients", missingClientCiphers, "and trustees", missingTrusteeCiphers)

	if p.relayState.numberOfConsecutiveFailedRounds >= p.relayState.MaxNumberOfConsecutiveFailedRounds {
		log.Error("MAX_NUMBER_OF_CONSECUTIVE_FAILED_ROUNDS (", p.relayState.MaxNumberOfConsecutiveFailedRounds,
			") reached, killing protocol.")

		log.Lvl3("Stopping experiment, if any.")
		missingClientCiphers, missingTrusteesCiphers := p.relayState.roundManager.MissingCiphersForCurrentRound()
		p.relayState.timeoutHandler(missingClientCiphers, missingTrusteesCiphers)
	} else {
		// cleanup, start the transition to next round
		log.Lvl1("Gonna Force close...")
		p.relayState.roundManager.Dump()
		p.relayState.roundManager.ForceCloseRound()
		p.relayState.roundManager.Dump()

		p.relayState.numberOfNonAckedDownstreamPackets-- // packet is not "in-flight" because it is lost

		// if we still have open rounds (after closing this one), we need to tell the DC-net to move to this new round
		if roundOpened, roundID := p.relayState.roundManager.currentRound(); roundOpened {
			//prepare for the next round (this empties the dc-net buffer, making them ready for a new round)
			p.relayState.DCNet.DecodeStart(roundID)
		}

		// if we can, open new rounds
		p.downstreamPhase_sendMany()

		// we should also try to finalize the next round
		if p.relayState.roundManager.HasAllCiphersForCurrentRound() {
			log.Lvl1("Timeouts: Following round was ready, calling hasAllCiphersForUpstream(true)")
			p.upstreamPhase1_processCiphers(true)
		}
	}
}

func (p *PriFiLibRelayInstance) timeoutRetransmitPk(msg *net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG) {

	time.Sleep(10 * time.Duration(p.relayState.RoundTimeOut) * time.Millisecond)

	log.Lvl1("Timeout fired")

	// never start treating two timeout concurrently (or receiving a message)
	p.relayState.processingLock.Lock()
	defer p.relayState.processingLock.Unlock()

	if !p.relayState.roundManager.IsRoundOpenend(0) {
		return //everything went well, it's great !
	}

	if p.stateMachine.State() == "SHUTDOWN" {
		return //nothing to ensure in that case
	}

	log.Lvl1("Timeout fired, continuing")

	// broadcast to all clients
	for i := 0; i < p.relayState.nClients; i++ {
		if !p.relayState.roundManager.clientAckMap[i] {
			log.Lvl1("Timeout: retransmitting all keys to client", i)
			p.messageSender.SendToClientWithLog(i, msg, "(client "+strconv.Itoa(i+1)+")")
		}
	}

}
