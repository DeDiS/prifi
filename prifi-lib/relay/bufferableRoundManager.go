package relay

import (
	"errors"
	"github.com/lbarman/prifi/prifi-lib/net"
	"gopkg.in/dedis/onet.v1/log"
	"strconv"
	"sync"
	"time"
)

// Stores ciphers for different rounds. Manages the transition between rounds, the rate limiting of trustees
type BufferableRoundManager struct {
	sync.Mutex

	//immutable
	nClients                    int
	nTrustees                   int
	maxNumberOfConcurrentRounds int

	//the ACK map for this round
	clientAckMap  map[int]bool
	trusteeAckMap map[int]bool

	//hold the real data. map(trustee/clientID -> map( roundID -> data))
	bufferedClientCiphers  map[int]map[int32][]byte
	bufferedTrusteeCiphers map[int]map[int32][]byte

	//we remember the last round we close for OpenNextRound()
	lastRoundClosed int32

	//remember who was the last owner, next is this+1
	lastOwner int

	//initially equal to 1 (the first round where the relay has downstream data), then happens after schedule
	nextOCSlotRound int32

	//we also store the data already sent, in case we need to resend it
	dataAlreadySent map[int32]*net.REL_CLI_DOWNSTREAM_DATA

	//when we open a round, we keep the start time to measure round duration
	openRounds map[int32]time.Time

	//holds the schedule, i.e. which ownerslot will be skipped in the future. Keys are in [0, nclients[
	storedOwnerSchedule map[int]bool

	//stop/resume functions when we have too much/little ciphers
	DoSendStopResumeMessages bool
	LowBound                 int //restart sending at lowerbound
	HighBound                int //stop sending at higherbound
	stopFunction             func(int)
	stopSent                 bool
	resumeFunction           func(int)
	resumeSent               bool
}

// NewBufferableRoundManager creates a Round Manager that handles the buffering of cipher, the rounds and their transitions, and the rate-limiting
func NewBufferableRoundManager(nClients, nTrustees, maxNumberOfConcurrentRounds int) *BufferableRoundManager {
	if nClients+nTrustees == 0 {
		log.Fatal("Can't init a BufferableRoundManager with no clients nor trustees")
	}

	b := new(BufferableRoundManager)

	b.nClients = nClients
	b.nTrustees = nTrustees
	b.maxNumberOfConcurrentRounds = maxNumberOfConcurrentRounds
	b.lastRoundClosed = -1 // next is round 0
	b.lastOwner = -1       // next is client 0
	b.nextOCSlotRound = 1  // first is 1, the first downstream data from relay

	b.resetACKmaps()

	b.dataAlreadySent = make(map[int32]*net.REL_CLI_DOWNSTREAM_DATA)
	b.openRounds = make(map[int32]time.Time)
	b.storedOwnerSchedule = nil

	b.bufferedClientCiphers = make(map[int]map[int32][]byte)
	b.bufferedTrusteeCiphers = make(map[int]map[int32][]byte)

	return b
}

// CurrentRound returns the current round, ie the smallest open round, or returns (false, -1) if no rounds are open
func (b *BufferableRoundManager) CurrentRound() int32 {
	b.Lock()
	defer b.Unlock()

	anyRoundOpen, round := b.currentRound()
	if !anyRoundOpen {
		log.Fatal("Tried to get CurrentRound(), but no round opened !")
	}

	return round
}

// CurrentRound returns the current round, ie the smallest open round, or returns (false, -1) if no rounds are open
func (b *BufferableRoundManager) currentRound() (bool, int32) {

	if len(b.openRounds) == 0 {
		return false, -1
	}

	var min int32 = 2147483647 //max value for int32
	for k := range b.openRounds {
		if k < min {
			min = k
		}
	}
	return true, min
}

// NextRoundToOpen returns the next round to open as RoundID. If none are open, uses the "lastRoundClosed"+1.
func (b *BufferableRoundManager) NextRoundToOpen() int32 {
	b.Lock()
	defer b.Unlock()

	return b.nextRoundToOpen()
}

// NextRoundToOpen returns the next round to open. If none are open, uses the "lastRoundClosed"+1. Does not skip the planned closed rounds.
func (b *BufferableRoundManager) nextRoundToOpen() int32 {
	anyRoundOpen, currentRound := b.currentRound()

	nextRoundCandidate := int32(0)
	if !anyRoundOpen {
		nextRoundCandidate = b.lastRoundClosed + 1
	} else {
		nextRoundCandidate = currentRound + 1
	}

	// shift while that round is already opened
	_, found := b.openRounds[nextRoundCandidate]

	// check already opened
	for found {
		nextRoundCandidate++
		_, found = b.openRounds[nextRoundCandidate]
	}

	return nextRoundCandidate
}

// UpdateAndGetNextOwnerID returns the next slot owner.
func (b *BufferableRoundManager) UpdateAndGetNextOwnerID() int {
	b.Lock()
	defer b.Unlock()

	return b.updateAndGetNextOwnerID()
}

func (b *BufferableRoundManager) updateAndGetNextOwnerID() int {

	nextOwnerIDCandidate := (b.lastOwner + 1) % b.nClients

	if b.storedOwnerSchedule == nil || len(b.storedOwnerSchedule) == 0 {

		b.lastOwner = nextOwnerIDCandidate
		return nextOwnerIDCandidate // valid since no schedule
	}

	open, found := b.storedOwnerSchedule[nextOwnerIDCandidate]

	// check if disabled in the schedule, iterate until find a non-closed slot (or go further than the schedule in time)
	loopCount := 0
	for found && !open {
		nextOwnerIDCandidate = (nextOwnerIDCandidate + 1) % b.nClients
		open, found = b.storedOwnerSchedule[nextOwnerIDCandidate]

		if loopCount == len(b.storedOwnerSchedule) {
			return -1 // all slots closed
		}
		loopCount++
	}

	b.lastOwner = nextOwnerIDCandidate
	return nextOwnerIDCandidate
}

// Open next round, fetch the buffered ciphers, reset the ACK map
func (b *BufferableRoundManager) OpenNextRound() int32 {
	b.Lock()
	defer b.Unlock()

	//make sure not to open more rounds than allowed
	if len(b.openRounds) >= b.maxNumberOfConcurrentRounds {
		log.Fatal("Tried to OpenNextRound(), but we have already", len(b.openRounds), "rounds opened.")
	}

	anyRoundOpen := false
	if len(b.openRounds) > 0 {
		anyRoundOpen = true
	}

	roundID := b.nextRoundToOpen()

	//open the round
	b.dataAlreadySent[roundID] = nil
	b.openRounds[roundID] = time.Now()

	//if no round was opened before, then by opening this one, you need to pull the already-buffered ciphers
	if !anyRoundOpen {
		b.resetACKmaps()
		//use the cipher we already stored
		for i := 0; i < b.nClients; i++ {
			if _, exists := b.bufferedClientCiphers[i][roundID]; exists {
				b.clientAckMap[i] = true
			}
		}
		for i := 0; i < b.nTrustees; i++ {
			if _, exists := b.bufferedTrusteeCiphers[i][roundID]; exists {
				b.trusteeAckMap[i] = true
			}
		}
	}

	return roundID
}

// CloseRound finalizes this round, returning all ciphers stored, then increasing the round number. Should only be called when HasAllCiphersForCurrentRound() == true
func (b *BufferableRoundManager) CollectRoundData() ([][]byte, [][]byte, error) {
	b.Lock()
	defer b.Unlock()

	anyRoundOpen, currentRoundID := b.currentRound()

	if !anyRoundOpen {
		return nil, nil, errors.New("Cannot collect round, none opened !")
	}
	if !b.hasAllCiphersForCurrentRound() {
		return nil, nil, errors.New("Cannot collect round " + strconv.Itoa(int(currentRoundID)) + " yet, missing ciphers.")
	}

	//prepare the output, discard those ciphers
	clientsOut := make([][]byte, 0)
	for i := 0; i < b.nClients; i++ {
		clientsOut = append(clientsOut, b.bufferedClientCiphers[i][currentRoundID])
		delete(b.bufferedClientCiphers[i], currentRoundID)
	}
	trusteesOut := make([][]byte, 0)
	for i := 0; i < b.nTrustees; i++ {
		trusteesOut = append(trusteesOut, b.bufferedTrusteeCiphers[i][currentRoundID])
		delete(b.bufferedTrusteeCiphers[i], currentRoundID)
	}

	return clientsOut, trusteesOut, nil
}

// CloseRound finalizes this round, returning all ciphers stored, then increasing the round number. Should only be called when HasAllCiphersForCurrentRound() == true
func (b *BufferableRoundManager) CloseRound() error {
	b.Lock()
	defer b.Unlock()

	anyRoundOpen, currentRoundID := b.currentRound()

	if !anyRoundOpen {
		return errors.New("Cannot close round, none opened !")
	}

	if !b.hasAllCiphersForCurrentRound() {
		return errors.New("Cannot close round " + strconv.Itoa(int(currentRoundID)) + ", does not have all ciphers")
	}

	//close current round
	delete(b.dataAlreadySent, currentRoundID)
	delete(b.openRounds, currentRoundID)

	//discard the buffered ciphers
	for i := 0; i < b.nClients; i++ {
		delete(b.bufferedClientCiphers[i], currentRoundID)
	}
	for i := 0; i < b.nTrustees; i++ {
		delete(b.bufferedTrusteeCiphers[i], currentRoundID)
	}

	//send rate changes if needed
	for trusteeID := range b.bufferedTrusteeCiphers {
		b.sendRateChangeIfNeeded(trusteeID)
	}

	b.lastRoundClosed = currentRoundID

	//reset the map
	b.resetACKmaps()

	anyRoundOpen, newRoundID := b.currentRound()

	//if anyround is open (several rounds were open before closing this one), use the buffered ciphers
	if anyRoundOpen {
		//use the cipher we already stored
		for i := 0; i < b.nClients; i++ {
			if _, exists := b.bufferedClientCiphers[i][newRoundID]; exists {
				b.clientAckMap[i] = true
			}
		}
		for i := 0; i < b.nTrustees; i++ {
			if _, exists := b.bufferedTrusteeCiphers[i][newRoundID]; exists {
				b.trusteeAckMap[i] = true
			}
		}
	}

	return nil
}

// isRoundOpen returns true IFF the round is in openRounds
func (b *BufferableRoundManager) isRoundOpen(roundID int32) bool {
	_, found := b.openRounds[roundID]
	return found
}

//return the time delta since the creation of the DCNetRound struct
func (b *BufferableRoundManager) TimeSpentInRound(roundID int32) time.Duration {
	b.Lock()
	defer b.Unlock()

	if startTime, found := b.openRounds[roundID]; found {
		return time.Since(startTime)
	}
	log.Fatal("Requested duration for round", roundID, ", but round has been closed already (or was not found).")
	return time.Hour
}

// resetACKmaps resets to 0 (all false) the two acks maps
func (b *BufferableRoundManager) resetACKmaps() {

	b.clientAckMap = make(map[int]bool)
	b.trusteeAckMap = make(map[int]bool)

	for i := 0; i < b.nClients; i++ {
		b.clientAckMap[i] = false
	}
	for i := 0; i < b.nTrustees; i++ {
		b.trusteeAckMap[i] = false
	}
}

// IsNextDownstreamRoundForOpenClosedRequest return true if the next downstream round should have flagOpenCloseScheduleRequest == true
func (b *BufferableRoundManager) IsNextDownstreamRoundForOpenClosedRequest(nClients int) bool {
	b.Lock()
	defer b.Unlock()
	return (b.nextRoundToOpen() == b.nextOCSlotRound)
}

// NextDownstreamRoundForOpenClosedRequest return the next downstream round should have flagOpenCloseScheduleRequest == true
func (b *BufferableRoundManager) NextDownstreamRoundForOpenClosedRequest() int32 {
	b.Lock()
	defer b.Unlock()
	return b.nextOCSlotRound
}

// SetStoredRoundSchedule stores the schedule, and resets the nextOwner to be 0
func (b *BufferableRoundManager) SetStoredRoundSchedule(s map[int]bool) {
	b.Lock()
	defer b.Unlock()

	b.storedOwnerSchedule = s

	//next OCSlotRound is right at the end of this schedule. maxKey != nClients
	numberOfOpenSlots := 0
	for _, isSlotOpen := range s {
		if isSlotOpen {
			numberOfOpenSlots++
		}
	}

	b.lastOwner = -1 //this resets the owner schedule

	_, currentRoundID := b.currentRound()
	//there will be numberOfOpenSlots after this one for data, then, next one is OC slot
	b.nextOCSlotRound = currentRoundID + int32(numberOfOpenSlots) + int32(b.maxNumberOfConcurrentRounds) + 1
}

// SetDataAlreadySent sets the "DataAlreadySent" field for the given round
func (b *BufferableRoundManager) SetDataAlreadySent(roundID int32, data *net.REL_CLI_DOWNSTREAM_DATA) {
	b.Lock()
	defer b.Unlock()

	if !b.isRoundOpen(roundID) {
		log.Fatal("Called SetDataAlreadySent(", roundID, "), but round is already closed.")
	}

	b.dataAlreadySent[roundID] = data
}

// GetDataAlreadySent gets the "DataAlreadySent" field for the given round
func (b *BufferableRoundManager) GetDataAlreadySent(roundID int32) *net.REL_CLI_DOWNSTREAM_DATA {
	b.Lock()
	defer b.Unlock()
	if data, found := b.dataAlreadySent[roundID]; found {
		return data
	}
	o, r := b.currentRound()
	log.Fatal("Requested data already sent for round", roundID, ", but round has been closed already (or was not found). Current round is", o, r)
	return nil
}

// AddTrusteeCipher adds a trustee cipher for a given round
func (b *BufferableRoundManager) AddTrusteeCipher(roundID int32, trusteeID int, data []byte) error {
	b.Lock()
	defer b.Unlock()

	_, currendRound := b.currentRound()
	//if !anyRoundOpenend {
	//	log.Fatal("Can't add trustee cipher, no round opened")
	//}

	if data == nil {
		return errors.New("Can't accept a nil trustee cipher")
	}
	if roundID < currendRound {
		return errors.New("Can't accept a trustee cipher in the past")
	}
	b.addToBuffer(&b.bufferedTrusteeCiphers, roundID, trusteeID, data)

	if roundID == currendRound {
		b.trusteeAckMap[trusteeID] = true
	}

	b.sendRateChangeIfNeeded(trusteeID)

	return nil
}

// AddClientCipher adds a client cipher for a given round
func (b *BufferableRoundManager) AddClientCipher(roundID int32, clientID int, data []byte) error {
	b.Lock()
	defer b.Unlock()

	anyRoundOpenend, currendRound := b.currentRound()
	if !anyRoundOpenend {
		log.Fatal("Can't add client cipher, no round opened")
	}

	if data == nil {
		return errors.New("Can't accept a nil client cipher")
	}
	if roundID < currendRound {
		return errors.New("Can't accept a client cipher in the past")
	}
	b.addToBuffer(&b.bufferedClientCiphers, roundID, clientID, data)

	if roundID == currendRound {
		b.clientAckMap[clientID] = true
	}

	return nil
}

// HasAllCiphersForCurrentRound returns true iff we received exactly one cipher for every client and trustee for this round
func (b *BufferableRoundManager) HasAllCiphersForCurrentRound() bool {
	b.Lock()
	defer b.Unlock()

	return b.hasAllCiphersForCurrentRound()
}

// hasAllCiphersForCurrentRound returns true iff we received exactly one cipher for every client and trustee for this round
func (b *BufferableRoundManager) hasAllCiphersForCurrentRound() bool {
	for _, v := range b.clientAckMap {
		if !v {
			return false
		}
	}
	for _, v := range b.trusteeAckMap {
		if !v {
			return false
		}
	}
	return true
}

// NumberOfBufferedCiphers returns the number of buffered ciphers for this trustee.
func (b *BufferableRoundManager) NumberOfBufferedCiphers(trusteeID int) int {
	return len(b.bufferedTrusteeCiphers[trusteeID])
}

// MissingCiphersForCurrentRound returns a pair of (clientIDs, trusteesIDs) where those entities did not send a cipher for this round
func (b *BufferableRoundManager) MissingCiphersForCurrentRound() ([]int, []int) {
	b.Lock()
	defer b.Unlock()

	clientMissing := make([]int, 0)
	for k, v := range b.clientAckMap {
		if !v {
			clientMissing = append(clientMissing, k)
		}
	}
	trusteeMissing := make([]int, 0)
	for k, v := range b.trusteeAckMap {
		if !v {
			trusteeMissing = append(trusteeMissing, k)
		}
	}

	return clientMissing, trusteeMissing
}

// IsRoundOpenend checks if we are in the given round (ie, used to check if we are stuck)
func (b *BufferableRoundManager) IsRoundOpenend(roundID int32) bool {
	b.Lock()
	defer b.Unlock()

	return b.isRoundOpen(roundID)
}

/**
 * Adds a component to the BufferManager, that reacts to the # of buffered cipher (per trustees), and call stopFn()
 * and resumeFn() when the bounds are reached
 */
func (b *BufferableRoundManager) AddRateLimiter(lowBound, highBound int, stopFunction, resumeFunction func(int)) error {
	if lowBound < 0 || lowBound > highBound {
		return errors.New("Lowbound must be > 0 and < highBound")
	}
	if highBound < lowBound {
		return errors.New("Highbound must be > lowBound")
	}
	if stopFunction == nil {
		return errors.New("Can't initiate a RateLimiter without a stop function")
	}
	if resumeFunction == nil {
		return errors.New("Can't initiate a RateLimiter without a resume function")
	}

	b.DoSendStopResumeMessages = true
	b.LowBound = lowBound
	b.HighBound = highBound
	b.stopFunction = stopFunction
	b.resumeFunction = resumeFunction

	return nil
}

func (b *BufferableRoundManager) sendRateChangeIfNeeded(trusteeID int) {
	if b.DoSendStopResumeMessages {
		n := b.NumberOfBufferedCiphers(trusteeID)
		if n >= b.HighBound && !b.stopSent {
			b.stopFunction(trusteeID)
			b.stopSent = true
			b.resumeSent = false
		} else if n <= b.LowBound && !b.resumeSent {
			b.resumeFunction(trusteeID)
			b.stopSent = false
			b.resumeSent = true
		}
	}
}

func (b *BufferableRoundManager) addToBuffer(bufferPtr *map[int]map[int32][]byte, roundID int32, entityID int, data []byte) {
	buffer := *bufferPtr
	if buffer[entityID] == nil {
		buffer[entityID] = make(map[int32][]byte)
	}

	buffer[entityID][roundID] = data
}
