package relay

import (
	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/net"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
	"math"
	"strconv"
)

// Received_CLI_REL_BLAME
func (p *PriFiLibRelayInstance) Received_CLI_REL_BLAME(msg net.CLI_REL_DISRUPTION_BLAME) error {

	// TODO: Check NIZK
	p.stateMachine.ChangeState("BLAMING")

	toSend := &net.REL_ALL_DISRUPTION_REVEAL{
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
func (p *PriFiLibRelayInstance) Received_CLI_REL_REVEAL(msg net.CLI_REL_DISRUPTION_REVEAL) error {

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
func (p *PriFiLibRelayInstance) Received_TRU_REL_REVEAL(msg net.TRU_REL_DISRUPTION_REVEAL) error {

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
				toSend := &net.REL_ALL_DISRUPTION_SECRET{
					UserID: clientID}
				p.messageSender.SendToTrustee(trusteeID, toSend)
				toSend2 := &net.REL_ALL_DISRUPTION_SECRET{
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
func (p *PriFiLibRelayInstance) Received_TRU_REL_SECRET(msg net.TRU_REL_DISRUPTION_SECRET) error {
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
func (p *PriFiLibRelayInstance) Received_CLI_REL_SECRET(msg net.CLI_REL_DISRUPTION_SECRET) error {
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
