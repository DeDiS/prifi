package utils

import (
	prifilog "github.com/lbarman/prifi/prifi-lib/log"
	"gopkg.in/dedis/onet.v1/log"
	"math"
	"time"
)

// PCAPReceivedPacket represents a PCAP that was transmitted through Prifi and received at the relay
type PCAPReceivedPacket struct {
	ID              uint32
	ReceivedAt      uint64
	SentAt          uint64
	Delay           uint64
	DataLen         uint32
	IsFinalFragment bool
}

// PCAPLog is a collection of PCAPReceivedPackets
type PCAPLog struct {
	receivedPackets []*PCAPReceivedPacket
	nextReport      time.Time
	period          time.Duration
}

// Returns an instantiated PCAPLog
func NewPCAPLog() *PCAPLog {
	p := &PCAPLog{
		receivedPackets: make([]*PCAPReceivedPacket, 0),
		period:          time.Duration(5) * time.Second,
		nextReport:      time.Now(),
	}
	return p
}

// should be called with the received pcap packet
func (pl *PCAPLog) ReceivedPcap(ID uint32, frag bool, tsSent uint64, tsExperimentStart uint64, dataLen uint32) {

	if pl.receivedPackets == nil {
		pl.receivedPackets = make([]*PCAPReceivedPacket, 0)
	}

	receptionTime := uint64(prifilog.MsTimeStampNow()) - tsExperimentStart

	if receptionTime < 0 {
		receptionTime = 0
	}

	p := &PCAPReceivedPacket{
		ID:              ID,
		ReceivedAt:      receptionTime,
		SentAt:          tsSent,
		Delay:           receptionTime - tsSent,
		DataLen:         dataLen,
		IsFinalFragment: frag,
	}


	log.Lvl1("Received pcap", p.ID, p.Delay, p.DataLen)

	pl.receivedPackets = append(pl.receivedPackets, p)

	now := time.Now()
	if now.After(pl.nextReport) {
		pl.Print()
		pl.nextReport = now.Add(pl.period)
	}
}

// prints current statistics for the pcap logger
func (pl *PCAPLog) Print() {

	totalPackets := 0
	totalUniquePackets := 0
	totalFragments := 0

	//compute min max and other stats
	delaysSum := uint64(0)
	delayMax := uint64(0)
	for _, v := range pl.receivedPackets {
		totalPackets++
		if v.IsFinalFragment {
			totalUniquePackets++
		} else {
			totalFragments++
		}

		delaysSum += v.Delay

		if v.Delay > delayMax {
			delayMax = v.Delay
		}
	}

	delayMean := float64(delaysSum) / float64(totalPackets)

	//now compute variance
	variance := float64(0)
	for _, v := range pl.receivedPackets {
		variance += (float64(v.Delay) - delayMean) * (float64(v.Delay) - delayMean)
	}

	variance = variance / float64(totalPackets)

	//compute stddev
	stddev := math.Sqrt(variance)

	log.Lvl1("PCAPLog : ", totalFragments, "fragments,", totalUniquePackets, "final,", totalPackets, "fragments+final; mean",
		math.Ceil(delayMean*100)/100, "ms, stddev", math.Ceil(stddev*100)/100, "max", math.Ceil(float64(delayMax)*100)/100, "ms")
}
