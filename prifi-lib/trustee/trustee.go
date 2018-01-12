package trustee

/*
PriFi Trustee
************
This regroups the behavior of the PriFi trustee.
Needs to be instantiated via the PriFiProtocol in prifi.go
Then, this file simple handle the answer to the different message kind :

- ALL_ALL_PARAMETERS - (specialized into ALL_TRU_PARAMETERS) - used to initialize the relay over the network / overwrite its configuration
- REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE - the client's identities (and ephemeral ones), and a base. We react by Neff-Shuffling and sending the result
- REL_TRU_TELL_TRANSCRIPT - the Neff-Shuffle's results. We perform some checks, sign the last one, send it to the relay, and follow by continuously sending ciphers.
- REL_TRU_TELL_RATE_CHANGE - Received when the relay requests a sending rate change, the message contains the necessary information needed to perform this change
*/

import (
	"errors"
	"github.com/lbarman/prifi/prifi-lib/config"
	"github.com/lbarman/prifi/prifi-lib/dcnet"
	"github.com/lbarman/prifi/prifi-lib/net"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
	"strconv"
	"time"
)

/*
Received_ALL_ALL_SHUTDOWN handles ALL_ALL_SHUTDOWN messages.
When we receive this message we should  clean up resources.
*/
func (p *PriFiLibTrusteeInstance) Received_ALL_ALL_SHUTDOWN(msg net.ALL_ALL_SHUTDOWN) error {
	log.Lvl1("Trustee " + strconv.Itoa(p.trusteeState.ID) + " : Received a SHUTDOWN message. ")

	//stop the sending process
	p.trusteeState.sendingRate <- TRUSTEE_KILL_SEND_PROCESS

	p.stateMachine.ChangeState("SHUTDOWN")

	return nil
}

/*
Received_ALL_ALL_PARAMETERS handles ALL_ALL_PARAMETERS.
It initializes the trustee with the parameters contained in the message.
*/
func (p *PriFiLibTrusteeInstance) Received_ALL_ALL_PARAMETERS(msg net.ALL_ALL_PARAMETERS) error {

	startNow := msg.BoolValueOrElse("StartNow", false)
	trusteeID := msg.IntValueOrElse("NextFreeTrusteeID", -1)
	nTrustees := msg.IntValueOrElse("NTrustees", p.trusteeState.nTrustees)
	nClients := msg.IntValueOrElse("NClients", p.trusteeState.nClients)
	cellSize := msg.IntValueOrElse("UpstreamCellSize", p.trusteeState.PayloadLength)
	dcNetType := msg.StringValueOrElse("DCNetType", "not initilaized")

	//sanity checks
	if trusteeID < -1 {
		return errors.New("trusteeID cannot be negative")
	}
	if nTrustees < 1 {
		return errors.New("nTrustees cannot be smaller than 1")
	}
	if nClients < 1 {
		return errors.New("nClients cannot be smaller than 1")
	}
	if cellSize < 1 {
		return errors.New("UpCellSize cannot be 0")
	}

	switch dcNetType {
	case "Simple":
		p.trusteeState.DCNet_RoundManager.CellCoder = dcnet.SimpleCoderFactory()
	case "Verifiable":
		p.trusteeState.DCNet_RoundManager.CellCoder = dcnet.OwnedCoderFactory()
	default:
		log.Fatal("DCNetType must be Simple or Verifiable")
	}

	p.trusteeState.ID = trusteeID
	p.trusteeState.Name = "Trustee-" + strconv.Itoa(trusteeID)
	p.trusteeState.nClients = nClients
	p.trusteeState.nTrustees = nTrustees
	p.trusteeState.PayloadLength = cellSize
	p.trusteeState.TrusteeID = trusteeID
	p.trusteeState.neffShuffle.Init(trusteeID, p.trusteeState.privateKey, p.trusteeState.PublicKey)

	//placeholders for pubkeys and secrets
	p.trusteeState.ClientPublicKeys = make([]abstract.Point, nClients)
	p.trusteeState.sharedSecrets = make([]abstract.Point, nClients)

	if startNow {
		// send our public key to the relay
		p.Send_TRU_REL_PK()
	}

	p.stateMachine.ChangeState("INITIALIZING")

	log.Lvlf5("%+v\n", p.trusteeState)
	log.Lvl2("Trustee " + strconv.Itoa(p.trusteeState.ID) + " has been initialized by message. ")
	return nil
}

/*
Send_TRU_REL_PK tells the relay's public key to the relay
(this, of course, provides no security, but this is an early version of the protocol).
This is the first action of the trustee.
*/
func (p *PriFiLibTrusteeInstance) Send_TRU_REL_PK() error {
	toSend := &net.TRU_REL_TELL_PK{TrusteeID: p.trusteeState.ID, Pk: p.trusteeState.PublicKey}
	p.messageSender.SendToRelayWithLog(toSend, "")
	return nil
}

/*
Send_TRU_REL_DC_CIPHER sends DC-net ciphers to the relay continuously once started.
One can control the rate by sending flags to "rateChan".
*/
func (p *PriFiLibTrusteeInstance) Send_TRU_REL_DC_CIPHER(rateChan chan int16) {

	stop := false
	currentRate := TRUSTEE_RATE_ACTIVE
	roundID := int32(0)

	for !stop {
		select {
		case newRate := <-rateChan:

			if currentRate != newRate {
				if (newRate == TRUSTEE_RATE_ACTIVE && !p.trusteeState.AlwaysSlowDown) {
					log.Lvl1("Trustee " + strconv.Itoa(p.trusteeState.ID) + " : rate changed from " + strconv.Itoa(int(currentRate)) + " to FULL")
				} else if (newRate == TRUSTEE_RATE_HALVED && !p.trusteeState.NeverSlowDown) {
					log.Lvl1("Trustee " + strconv.Itoa(p.trusteeState.ID) + " : rate changed from " + strconv.Itoa(int(currentRate)) + " to HALVED")
				}
				currentRate = newRate
			}

			if newRate == TRUSTEE_KILL_SEND_PROCESS {
				stop = true
			}

		default:
			if currentRate == TRUSTEE_RATE_ACTIVE {
				if p.trusteeState.AlwaysSlowDown {
					log.Lvl4("Trustee " + strconv.Itoa(p.trusteeState.ID) + " rate FULL, sleeping for " + strconv.Itoa(p.trusteeState.BaseSleepTime))
					time.Sleep(time.Duration(p.trusteeState.BaseSleepTime) * time.Millisecond)
				}
				newRoundID, err := sendData(p, roundID)
				if err != nil {
					stop = true
				}
				roundID = newRoundID

			} else if currentRate == TRUSTEE_RATE_HALVED {
				if !p.trusteeState.NeverSlowDown {
					//sorry double neg. If NeverSlowDown = true, we skip this sleep
					log.Lvl4("Trustee " + strconv.Itoa(p.trusteeState.ID) + " rate HALVED, sleeping for " + strconv.Itoa(p.trusteeState.BaseSleepTime))
					time.Sleep(time.Duration(p.trusteeState.BaseSleepTime) * time.Millisecond)
				}
				newRoundID, err := sendData(p, roundID)
				if err != nil {
					stop = true
				}
				roundID = newRoundID

			} else {
				log.Lvl2("Trustee " + strconv.Itoa(p.trusteeState.ID) + " : In unrecognized sending state")
			}

		}
	}
	log.Lvl2("Trustee " + strconv.Itoa(p.trusteeState.ID) + " : Stopped.")
}

/*
Received_REL_TRU_TELL_RATE_CHANGE handles REL_TRU_TELL_RATE_CHANGE messages
by changing the cipher sending rate.
Either the trustee must stop sending because the relay is at full capacity
or the trustee sends normally because the relay has emptied up enough capacity.
*/
func (p *PriFiLibTrusteeInstance) Received_REL_TRU_TELL_RATE_CHANGE(msg net.REL_TRU_TELL_RATE_CHANGE) error {

	if msg.WindowCapacity == 0 {
		p.trusteeState.sendingRate <- TRUSTEE_RATE_HALVED
	} else {
		p.trusteeState.sendingRate <- TRUSTEE_RATE_ACTIVE
	}

	return nil
}

/*
sendData is an auxiliary function used by Send_TRU_REL_DC_CIPHER. It computes the DC-net's cipher and sends it.
It returns the new round number (previous + 1).
*/
func sendData(p *PriFiLibTrusteeInstance, roundID int32) (int32, error) {
	data := p.trusteeState.DCNet_RoundManager.TrusteeEncode(p.trusteeState.PayloadLength)

	//send the data
	toSend := &net.TRU_REL_DC_CIPHER{
		RoundID:   roundID,
		TrusteeID: p.trusteeState.ID,
		Data:      data}
	if !p.messageSender.SendToRelayWithLog(toSend, "(round " + strconv.Itoa(int(roundID)) + ")") {
		return -1, errors.New("Could not send")
	}

	return roundID + 1, nil
}

/*
Received_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE handles REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE messages.
Those are sent when the connection to a relay is established.
They contain the long-term and ephemeral public keys of the clients,
and a base given by the relay. In addition to deriving the secrets,
the trustee uses the ephemeral keys to perform a Neff shuffle. It remembers
this shuffle in order to check the correctness of the chain of shuffle afterwards.
*/
func (p *PriFiLibTrusteeInstance) Received_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE(msg net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE) error {

	//begin parsing the message
	clientsPks := msg.Pks
	clientsEphemeralPks := msg.EphPks

	//sanity check
	if len(clientsPks) < 1 {
		e := "Trustee " + strconv.Itoa(p.trusteeState.ID) + " : len(clientsPks) must be >= 1"
		log.Error(e)
		return errors.New(e)
	}
	if len(clientsEphemeralPks) < 1 {
		e := "Trustee " + strconv.Itoa(p.trusteeState.ID) + " : len(clientsEphemeralPks) must be >= 1"
		log.Error(e)
		return errors.New(e)
	}
	if len(clientsPks) != len(clientsEphemeralPks) {
		e := "Trustee " + strconv.Itoa(p.trusteeState.ID) + " : len(clientsPks) must be == len(clientsEphemeralPks)"
		log.Error(e)
		return errors.New(e)
	}

	//fill in the clients keys
	for i := 0; i < len(clientsPks); i++ {
		p.trusteeState.ClientPublicKeys[i] = clientsPks[i]
		p.trusteeState.sharedSecrets[i] = config.CryptoSuite.Point().Mul(clientsPks[i], p.trusteeState.privateKey)
	}

	//set up the DC-nets
	sharedPRNGs := make([]abstract.Cipher, p.trusteeState.nClients)
	for i := 0; i < p.trusteeState.nClients; i++ {
		bytes, err := p.trusteeState.sharedSecrets[i].MarshalBinary()
		if err != nil {
			return errors.New("Could not marshal point !")
		}
		sharedPRNGs[i] = config.CryptoSuite.Cipher(bytes)
	}

	p.trusteeState.DCNet_RoundManager.TrusteeSetup(p.trusteeState.sharedSecrets)
	vkey := p.trusteeState.DCNet_RoundManager.CellCoder.TrusteeSetup(config.CryptoSuite, sharedPRNGs)
	//In case we use the simple dcnet, vkey isn't needed
	if vkey == nil {
		vkey = make([]byte, 1)
	}

	toSend, err := p.trusteeState.neffShuffle.ReceivedShuffleFromRelay(msg.Base, msg.EphPks, true, vkey)
	if err != nil {
		return errors.New("Could not do ReceivedShuffleFromRelay, error is " + err.Error())
	}

	//send the answer
	p.messageSender.SendToRelayWithLog(toSend, "")

	p.stateMachine.ChangeState("SHUFFLE_DONE")

	return nil
}

/*
Received_REL_TRU_TELL_TRANSCRIPT handles REL_TRU_TELL_TRANSCRIPT messages.
Those are sent when all trustees have already shuffled. They need to verify all the shuffles, and also that
their own shuffle has been included in the chain of shuffles. If that's the case, this trustee signs the *last*
shuffle (which will be used by the clients), and sends it back to the relay.
If everything succeed, starts the goroutine for sending DC-net ciphers to the relay.
*/
func (p *PriFiLibTrusteeInstance) Received_REL_TRU_TELL_TRANSCRIPT(msg net.REL_TRU_TELL_TRANSCRIPT) error {

	toSend, err := p.trusteeState.neffShuffle.ReceivedTranscriptFromRelay(msg.Bases, msg.GetKeys(), msg.GetProofs())
	if err != nil {
		return errors.New("Could not do ReceivedTranscriptFromRelay, error is " + err.Error())
	}

	//send the answer
	p.messageSender.SendToRelayWithLog(toSend, "")

	//we can forget our shuffle
	//p.trusteeState.neffShuffleToVerify = NeffShuffleResult{base2, ephPublicKeys2, proof}

	p.stateMachine.ChangeState("READY")

	//everything is ready, we start sending
	go p.Send_TRU_REL_DC_CIPHER(p.trusteeState.sendingRate)

	return nil
}

/*
Received_REL_ALL_REVEAL handles REL_ALL_REVEAL messages.
We send back one bit per client, from the shared cipher, at bitPos
*/
func (p *PriFiLibTrusteeInstance) Received_REL_ALL_REVEAL(msg net.REL_ALL_DISRUPTION_REVEAL) error {
	p.stateMachine.ChangeState("BLAMING")
	bits := p.trusteeState.DCNet_RoundManager.RevealBits(msg.RoundID, msg.BitPos, p.trusteeState.PayloadLength)
	toSend := &net.TRU_REL_DISRUPTION_REVEAL{
		TrusteeID: p.trusteeState.ID,
		Bits:      bits}
	p.messageSender.SendToRelayWithLog(toSend, "Revealed bits")
	return nil
}

/*
Received_REL_ALL_SECRET handles REL_ALL_SECRET messages.
We send back the shared secret with the indicated client
*/
func (p *PriFiLibTrusteeInstance) Received_REL_ALL_SECRET(msg net.REL_ALL_DISRUPTION_SECRET) error {

	secret := p.trusteeState.sharedSecrets[msg.UserID]
	toSend := &net.TRU_REL_DISRUPTION_SECRET{
		Secret: secret,
		NIZK:   make([]byte, 0)}
	p.messageSender.SendToRelayWithLog(toSend, "Sent secret to relay")
	return nil
}
