package utils

import (
	prifilog "github.com/lbarman/prifi/prifi-lib/log"
	"gopkg.in/dedis/onet.v1/log"
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
}

// should be called with the received pcap packet
func (pl *PCAPLog) ReceivedPcap(ID uint32, frag bool, tsSent uint64, tsExperimentStart uint64, dataLen uint32) {

	if pl.receivedPackets == nil {
		pl.receivedPackets = make([]*PCAPReceivedPacket, 0)
	}

	now := uint64(prifilog.MsTimeStampNow()) - tsExperimentStart

	p := &PCAPReceivedPacket{
		ID:              ID,
		ReceivedAt:      now,
		SentAt:          tsSent,
		Delay:           now - tsSent,
		DataLen:         dataLen,
		IsFinalFragment: frag,
	}

	pl.receivedPackets = append(pl.receivedPackets, p)
	pl.Print()
}

// prints current statistics for the pcap logger
func (pl *PCAPLog) Print() {

	totalPackets := 0
	totalUniquePackets := 0
	totalFragments := 0

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

	log.Lvl1("PCAPLog : ", totalFragments, "fragments,", totalUniquePackets, "final packets, ", totalPackets, " packets; mean", delayMean, "ms, max", delayMax, "ms")
}
