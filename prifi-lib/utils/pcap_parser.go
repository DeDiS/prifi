package utils

import (
	"errors"
	"github.com/Lukasa/gopcap"
	"gopkg.in/dedis/onet.v1/log"
	"math/rand"
	"os"
)

// Packet is an ID(Packet number), TimeSent in microsecond, and some Data
type Packet struct {
	ID       uint32
	TimeSent int64 //microseconds
	Data     []byte
}

// Parses a .pcap file, and returns all valid packets. A packet is (ID, TimeSent [micros], Data)
func ParsePCAP(path string) ([]Packet, error) {
	pcapfile, err := os.Open(path)
	if err != nil {
		return nil, errors.New("Cannot open" + path + "error is" + err.Error())
	}
	parsed, err := gopcap.Parse(pcapfile)
	if err != nil {
		return nil, errors.New("Cannot prase" + path + "error is" + err.Error())
	}

	out := make([]Packet, 0)

	if len(parsed.Packets) == 0 {
		return out, nil
	}

	timeDelta := parsed.Packets[0].Timestamp.Nanoseconds()
	for id, pkt := range parsed.Packets {

		p := Packet{
			ID:       uint32(id),
			Data:     getPayloadOrRandom(pkt),
			TimeSent: (pkt.Timestamp.Nanoseconds() - timeDelta) / 1000,
		}

		//basic sanity check
		if p.TimeSent > 0 && len(p.Data) != 0 {
			out = append(out, p)
		}

	}

	return out, nil
}

func getPayloadOrRandom(pkt gopcap.Packet) []byte {
	len := pkt.IncludedLen

	if pkt.Data == nil {
		return randomBytes(len)
	}

	return pkt.Data.LinkData().InternetData().TransportData()
}

func randomBytes(len uint32) []byte {
	if len == uint32(0) {
		return make([]byte, 0)
	}
	out := make([]byte, len)
	written, err := rand.Read(out)
	if err == nil {
		log.Fatal("Could not generate a random packet of length", len, "error is", err)
	}
	if uint32(written) != len {
		log.Fatal("Could not generate a random packet of length", len, "only wrote", written)
	}
	return out
}
