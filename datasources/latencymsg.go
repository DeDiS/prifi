package datasources

import (
	"encoding/binary"
	"strconv"
	"time"
)

const pattern uint16 = uint16(43690) //1010101010101010
const latencyMsgLength int = 12      // 4bytes roundID + 8bytes timeStamp

func genLatencyMessagePayload(creationTime time.Time, roundID int32) []byte {
	latencyMsgBytes := make([]byte, 12)
	currTime := MsTimeStamp(creationTime) //timestamp in Ms
	binary.BigEndian.PutUint32(latencyMsgBytes[0:4], uint32(roundID))
	binary.BigEndian.PutUint64(latencyMsgBytes[4:12], uint64(currTime))
	return latencyMsgBytes
}

// LatencyMessagesToBytes encoded the Latency messages in "msgs", returns the encoded bytes and the new "msgs" without the successfully-encoded messages
func LatencyMessagesToBytes(msgs []*LatencyTestToSend, clientID int, roundID int32, payLoadLength int, reportFunction func(int64)) ([]byte, []*LatencyTestToSend) {
	if len(msgs) == 0 {
		return make([]byte, 0), msgs
	}

	if payLoadLength < 18 {
		panic("Trying to do a Latency test, but payload is smaller than 18 bytes.")
	}

	// [0:2] PATTERN
	// [2:4] Number of messages
	// [4:6] ClientID
	// [6:10] RoundID
	// [10:18] Time of sending

	buffer := make([]byte, payLoadLength)
	binary.BigEndian.PutUint16(buffer[0:2], pattern)
	//later, put number of messages in [2;4]
	binary.BigEndian.PutUint16(buffer[4:6], uint16(clientID))
	posInBuffer := 6

	//pack all the latency messages we can in one
	numberOfMessagesPacked := uint16(0)
	for len(msgs) > 0 && posInBuffer+latencyMsgLength <= payLoadLength {

		//encode the first message
		b := genLatencyMessagePayload(msgs[0].CreatedAt, roundID)

		//save bytes in global buffer
		copy(buffer[posInBuffer:], b)

		//this is used to compute the "time stayed in buffer"
		reportFunction(MsTimeStampNow() - MsTimeStamp(msgs[0].CreatedAt))

		//pop the stack
		if len(msgs) == 1 {
			msgs = make([]*LatencyTestToSend, 0)
		} else {
			msgs = msgs[1:]
		}

		//we just packed one extra message
		numberOfMessagesPacked++
		posInBuffer += latencyMsgLength
	}
	binary.BigEndian.PutUint16(buffer[2:4], numberOfMessagesPacked)

	return buffer, msgs
}

// DecodeLatencyMessages tries to decode Latency messages, and calls actionFunction with (originalRoundId, roundDiff, timeDiff)
// for every found message
func DecodeLatencyMessages(buffer []byte, clientID int, receptionRoundID int32, actionFunction func(int32, int32, int64)) {

	//check if it is a latency message
	patternComp := uint16(binary.BigEndian.Uint16(buffer[0:2]))
	if patternComp != pattern {
		return
	}

	//get the number of timestamps, and check the size
	nMessages := int(binary.BigEndian.Uint16(buffer[2:4]))
	if 4+(nMessages)*latencyMsgLength > len(buffer) {
		panic("Invalid message, " + strconv.Itoa(nMessages) + " msg, but size is " + strconv.Itoa(len(buffer)))
	}

	//check that it is our messages
	clientIDcomp := int(binary.BigEndian.Uint16(buffer[4:6]))
	if clientIDcomp != clientID {
		return
	}

	for i := 0; i < nMessages; i++ {
		startPos := 6 + i*latencyMsgLength

		originalRoundID := int32(binary.BigEndian.Uint32(buffer[startPos : startPos+4]))
		timestamp := int64(binary.BigEndian.Uint64(buffer[startPos+4 : startPos+12]))

		//compute the diffs
		diff := MsTimeStampNow() - timestamp
		roundDiff := receptionRoundID - originalRoundID

		actionFunction(originalRoundID, roundDiff, diff)
	}
	return
}
