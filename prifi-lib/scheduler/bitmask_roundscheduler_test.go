package scheduler

import (
	"fmt"
	"testing"
)

func Test1Client(t *testing.T) {

	bmc := new(BitMaskSlotScheduler_Client)

	//arbitrary constants for this test
	mySlot := 4 //we are c2, assigned to slot 2
	nClients := 5

	//0:c0, 1:c1, ... 4:c4, 5:c0, ... 10:c0, ... 12:c2, 13:c3, 14:c4, 15:c0

	//relay starts by sending a downstream message (for round currentRound) with OpenClosedSchedRequest=true
	//client notice it, instead of sending the next upstream traffic, he will send the OCSchedule
	bmc.Client_ReceivedScheduleRequest(nClients)

	//12:SCHEDULE, 13:c2, 14:c3, 15:c4, 16:c0

	bmc.Client_ReserveRound(mySlot)

	contribution := bmc.Client_GetOpenScheduleContribution()

	if len(contribution) != 1 {
		t.Error("Contribution should have length 1, has length", len(contribution))
	}

	//The contribution is sent to the relay
	bmr := new(BitMaskSlotScheduler_Relay)

	finalSched := bmr.Relay_ComputeFinalSchedule(contribution, nClients)

	if len(finalSched) != nClients {
		fmt.Println(finalSched)
		t.Error("finalSched should have length", nClients, ", has length", len(finalSched))
	}

	if !finalSched[mySlot] {
		t.Error("finalSched should have slot", mySlot, "open")
	}
}

func Test2Client(t *testing.T) {

	bmc1 := new(BitMaskSlotScheduler_Client)
	bmc2 := new(BitMaskSlotScheduler_Client)

	//arbitrary constants for this test
	mySlot1 := 3 //we are c0 assigned to 3
	mySlot2 := 4 //we are c1 assigned to 4
	nClients := 5

	//relay starts by sending a downstream message (for round currentRound) with OpenClosedSchedRequest=true
	//client notice it, instead of sending the next upstream traffic, he will send the OCSchedule
	bmc1.Client_ReceivedScheduleRequest(nClients)
	bmc2.Client_ReceivedScheduleRequest(nClients)

	bmc1.Client_ReserveRound(mySlot1)
	bmc2.Client_ReserveRound(mySlot2)

	contribution1 := bmc1.Client_GetOpenScheduleContribution()
	contribution2 := bmc2.Client_GetOpenScheduleContribution()

	if len(contribution1) != 1 {
		t.Error("Contribution should have length 1, has length", len(contribution1))
	}
	if len(contribution2) != 1 {
		t.Error("Contribution should have length 1, has length", len(contribution2))
	}

	//The contribution is sent to the relay
	bmr := new(BitMaskSlotScheduler_Relay)

	contributions := bmr.Relay_CombineContributions(contribution1, contribution2)
	finalSched := bmr.Relay_ComputeFinalSchedule(contributions, nClients)

	if len(finalSched) != nClients {
		t.Error("finalSched should have length", nClients, ", has length", len(finalSched))
	}

	if !finalSched[mySlot1] {
		t.Error("finalSched should have slot", mySlot1, "open")
	}

	if !finalSched[mySlot2] {
		t.Error("finalSched should have slot", mySlot2, "open")
	}

	fmt.Println(finalSched)
}
