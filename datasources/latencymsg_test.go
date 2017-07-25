package datasources

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestLatencyMessages(t *testing.T) {

	latencyTests := make([]*LatencyTestToSend, 0)

	now := time.Now()
	newLatTest := &LatencyTestToSend{
		CreatedAt: now.Add(-10 * time.Second),
	}
	latencyTests = append(latencyTests, newLatTest)
	newLatTest = &LatencyTestToSend{
		CreatedAt: now.Add(-1 * time.Second),
	}
	latencyTests = append(latencyTests, newLatTest)

	clientID := 2
	roundID := int32(4)
	payloadLength := 100
	logFn := func(timeDiff int64) {
		fmt.Println(timeDiff)
	}
	bytes, outMsgs := LatencyMessagesToBytes(latencyTests, clientID, roundID, payloadLength, logFn)
	latencyTests = outMsgs

	fmt.Println(hex.Dump(bytes))

	actionFunction := func(roundRec int32, roundDiff int32, timeDiff int64) {
		fmt.Println("Latency is", timeDiff, "received on round", roundRec, "=> round diff is", roundDiff)
	}
	receptionRoundID := int32(20)
	DecodeLatencyMessages(bytes, clientID, receptionRoundID, actionFunction)
}
