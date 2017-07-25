package datasources

import (
	"testing"
	"time"
	"fmt"
)

func TestPingMessage(t *testing.T) {

	clientID := 2
	payloadLength := 100
	interval := time.Second

	fnPingSent := func(t int64){
		fmt.Println("Ping sent after staying", t, "ms in buffer")
	}
	fnPingReceived := func(originalRoundID int32, roundDiff int32, lat int64) {
		fmt.Println("Ping received", originalRoundID, roundDiff, lat)
	}

	dataSource := NewDataSourcePings(interval, clientID, fnPingSent, fnPingReceived)

	if dataSource.HasData() {
		t.Error("Should have data before Interval")
	}
	currentRound := int32(2)
	data := dataSource.GetDataFromSource(currentRound, payloadLength)
	if len(data) != 0 {
		t.Error("Should have data before Interval")
	}

	time.Sleep(interval)
	time.Sleep(100 * time.Millisecond)

	if !dataSource.HasData() {
		t.Error("Should now have data")
	}
	currentRound = int32(20)
	data = dataSource.GetDataFromSource(currentRound, payloadLength)
	if len(data) == 0 {
		t.Error("Should have data before Interval")
	}

	//goes through DC-net, gets back
	dataSource.SendDataToSource(25, data)
}
