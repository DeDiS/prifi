package datasources

import (
	"sync"
	"time"
)

// One buffered latency test message. We only need to store the "createdAt" time.
type LatencyTestToSend struct {
	CreatedAt time.Time
}

//The DataSource structure
type DataSourcePings struct {
	sync.Mutex
	LatencyTestsInterval time.Duration
	LatencyTestsToSend   []*LatencyTestToSend //lock the mutex before accessing this
	PingSentFunction	func(int64) //(timeStayedInBuffer)
	PingReceivedFunction func(int32, int32, int64) //(originalRoundId, roundDiff, timeDiff)
	ClientID	     int
}

func NewDataSourcePings(interval time.Duration, clientID int, pingSentFunction func(int64), pingReceivedFunction func(int32, int32, int64)) *DataSourcePings {

	dsp := &DataSourcePings{
		LatencyTestsInterval: interval,
		LatencyTestsToSend:   make([]*LatencyTestToSend, 0),
		PingSentFunction: pingSentFunction,
		PingReceivedFunction: pingReceivedFunction,
		ClientID: 	clientID,
	}

	go dsp.latencyMsgGenerator(interval)

	return dsp
}

// periodically generates latency test messages
func (dsp *DataSourcePings) latencyMsgGenerator(interval time.Duration) {
	for {
		time.Sleep(interval)

		dsp.Lock()
		// create a new latency test message
		newLatTest := &LatencyTestToSend{
			CreatedAt: time.Now(),
		}
		dsp.LatencyTestsToSend = append(dsp.LatencyTestsToSend, newLatTest)
		dsp.Unlock()
	}
}

func (dsp *DataSourcePings) HasData() bool {
	dsp.Lock()
	defer dsp.Unlock()

	return (len(dsp.LatencyTestsToSend) != 0)
}

func (dsp *DataSourcePings) GetDataFromSource(currentRoundID int32, payloadLength int) ([]byte) {
	dsp.Lock()
	defer dsp.Unlock()

	data, newList := LatencyMessagesToBytes(dsp.LatencyTestsToSend, dsp.ClientID, currentRoundID, payloadLength, dsp.PingSentFunction)
	dsp.LatencyTestsToSend = newList

	return data
}

func (dsp *DataSourcePings) AckDataToSource(int) {
	//no ACK for pings
}

func (dsp *DataSourcePings) SendDataToSource(receivedOnRound int32, data []byte) {
	DecodeLatencyMessages(data, dsp.ClientID, receivedOnRound, dsp.PingReceivedFunction)
}
