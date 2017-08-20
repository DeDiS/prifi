package scheduler

import (
	"math"
	"strconv"
)

// SlotScheduler is a protocol between the relay and the clients that allows to decide which slots are gonna be
// "open" (fixed-length byte array) or "closed" (inexistant, no message at all)
type SlotScheduler interface {

	//the client receives a new schedule request from the relay
	Client_ReceivedScheduleRequest()

	//the client alters the schedule being computed, and ask to transmit
	Client_ReserveRound(roundID int32)

	//return the schedule to send as payload
	Client_GetOpenScheduleContribution() []byte

	//Called with each client's contribution
	Relay_CombineContributions(contributions ...[]byte) []byte

	//returns all contributions in forms of a map of open slots
	Relay_ComputeFinalSchedule() map[int32]bool
}

// BitMaskScheduler_Client holds the info necessary for a client to compute his "contribution", or part of the bitmask
type BitMaskSlotScheduler_Client struct {
	NClients            int
	beginningOfRound    int32
	ClientWantsToSend   bool
	MyRoundInNextRounds int
}

// BitMaskScheduler_Relay
type BitMaskSlotScheduler_Relay struct {
}

// Client_ReceivedScheduleRequest instantiates the fields of BitMaskScheduler_Client
func (bmc *BitMaskSlotScheduler_Client) Client_ReceivedScheduleRequest(beginningOfRound int32, nClients int) {
	bmc.NClients = nClients
	bmc.beginningOfRound = beginningOfRound
	bmc.ClientWantsToSend = false
	bmc.MyRoundInNextRounds = -1
}

// Client_ReserveRound indicates to reserve a slot in the next round
func (bmc *BitMaskSlotScheduler_Client) Client_ReserveRound(slotID int32) {
	if slotID < bmc.beginningOfRound {
		panic("Cannot reserve slot " + strconv.Itoa(int(slotID)) + " since next scheduled round starts at slot " + strconv.Itoa(int(bmc.beginningOfRound)))
	}

	slotIDInNextRound := slotID - bmc.beginningOfRound
	bmc.MyRoundInNextRounds = int(slotIDInNextRound)
	bmc.ClientWantsToSend = true
}

// Client_GetOpenScheduleContribution computes their contribution as a bit array
func (bmc *BitMaskSlotScheduler_Client) Client_GetOpenScheduleContribution() []byte {
	//length of the contribution is nClients/8 bytes
	nBytes := int(math.Ceil(float64(bmc.NClients) / 8))
	payload := make([]byte, nBytes)

	if !bmc.ClientWantsToSend {
		return payload //all zeros
	}

	//set a bit to 1 at the correct position
	whichByte := int(math.Floor(float64(bmc.MyRoundInNextRounds) / 8))
	whichBit := uint(bmc.MyRoundInNextRounds % 8)
	payload[whichByte] = 1 << whichBit
	return payload
}

// Relay_CombineContributions combines (XOR) the received contributions from each clients. In the real DC-net,
// this is done automatically by the DC-net
func (bmr *BitMaskSlotScheduler_Relay) Relay_CombineContributions(contributions ...[]byte) []byte {
	out := make([]byte, len(contributions[0]))
	for j := range contributions {
		for i := range contributions[j] {
			out[i] ^= contributions[j][i]
		}
	}
	return out
}

// Relay_ComputeFinalSchedule computes the map[int32]bool of open slots in the next round given the stored contributions
func (bmr *BitMaskSlotScheduler_Relay) Relay_ComputeFinalSchedule(allContributions []byte, baseRoundID int32, maxSlots int) map[int32]bool {

	//this schedules goes from [baseRoundID; baseRoundID+maxSlots[
	endRoundID := baseRoundID + int32(maxSlots) - 1
	res := make(map[int32]bool)

	for byteIndex, b := range allContributions {
		for bitPos := uint(0); bitPos < 8; bitPos++ {
			roundID := baseRoundID + int32(byteIndex*8+int(bitPos))
			val := b & (1 << bitPos)
			if val > 0 { //the bit was set
				res[roundID] = true
			} else {
				res[roundID] = false
			}
			if roundID == endRoundID {
				return res
			}
		}
	}

	return res
}
