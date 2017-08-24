package scheduler

import (
	"math"
)

// SlotScheduler is a protocol between the relay and the clients that allows to decide which slots are gonna be
// "open" (fixed-length byte array) or "closed" (inexistant, no message at all)
type SlotScheduler interface {

	//the client receives a new schedule request from the relay
	Client_ReceivedScheduleRequest()

	//the client alters the schedule being computed, and ask to transmit
	Client_ReserveRound(slotID int)

	//return the schedule to send as payload
	Client_GetOpenScheduleContribution() []byte

	//Called with each client's contribution
	Relay_CombineContributions(contributions ...[]byte) []byte

	//returns all contributions in forms of a map of open slots
	Relay_ComputeFinalSchedule() map[int]bool
}

// BitMaskScheduler_Client holds the info necessary for a client to compute his "contribution", or part of the bitmask
type BitMaskSlotScheduler_Client struct {
	NClients          int
	ClientWantsToSend bool
	MySlotID          int
}

// BitMaskScheduler_Relay
type BitMaskSlotScheduler_Relay struct {
}

// Client_ReceivedScheduleRequest instantiates the fields of BitMaskScheduler_Client
func (bmc *BitMaskSlotScheduler_Client) Client_ReceivedScheduleRequest(nClients int) {
	bmc.NClients = nClients
	bmc.ClientWantsToSend = false
}

// Client_ReserveRound indicates to reserve a slot in the next round
func (bmc *BitMaskSlotScheduler_Client) Client_ReserveRound(slotID int) {
	bmc.MySlotID = slotID
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
	whichByte := int(math.Floor(float64(bmc.MySlotID) / 8))
	whichBit := uint(bmc.MySlotID % 8)
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
func (bmr *BitMaskSlotScheduler_Relay) Relay_ComputeFinalSchedule(allContributions []byte, maxSlots int) map[int]bool {

	//this schedules goes from [0; maxSlots[
	res := make(map[int]bool)

	for byteIndex, b := range allContributions {
		for bitPos := uint(0); bitPos < 8; bitPos++ {
			ownerID := int(byteIndex*8 + int(bitPos))
			val := b & (1 << bitPos)
			if val > 0 { //the bit was set
				res[ownerID] = true
			} else {
				res[ownerID] = false
			}
			if ownerID == maxSlots-1 {
				return res
			}
		}
	}

	return res
}
