package utils

import (
	"errors"
	"github.com/Lukasa/gopcap"
	"gopkg.in/dedis/onet.v1/log"
	"math/rand"
	"os"
	"encoding/binary"
)

const pattern uint16 = uint16(21845) //0101010101010101
const metaMessageLength int = 10      // 2bytes pattern + 8bytes timeStamp

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
		return nil, errors.New("Cannot parse" + path + "error is" + err.Error())
	}

	out := make([]Packet, 0)

	if len(parsed.Packets) == 0 {
		return out, nil
	}

	timeDelta := parsed.Packets[0].Timestamp.Nanoseconds()
	for id, pkt := range parsed.Packets {

		p := Packet{
			ID:       uint32(id),
			Data:     getPayloadOrRandom(pkt, uint32(id)),
			TimeSent: (pkt.Timestamp.Nanoseconds() - timeDelta) / 1000,
		}

		//basic sanity check
		if p.TimeSent > 0 && len(p.Data) != 0 {
			out = append(out, p)
		}

	}

	return out, nil
}

func getPayloadOrRandom(pkt gopcap.Packet, packetID uint32) []byte {
	len := pkt.IncludedLen

	if true || pkt.Data == nil {
		timeMs := pkt.Timestamp.Nanoseconds()/1000000
		return metaBytes(int(len), packetID, timeMs)
	}

	return pkt.Data.LinkData().InternetData().TransportData()
}

func metaBytes(length int, packetID uint32, timeSentInPcap int64) []byte {
	if length < metaMessageLength {
		return recognizableBytes(length, packetID)
	}
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out[0:2], pattern)
	binary.BigEndian.PutUint64(out[2:10], uint64(timeSentInPcap))
	return out
}

func recognizableBytes(length int, packetID uint32) []byte {
	if length == 0 {
		return make([]byte, 0)
	}
	pattern := make([]byte, 4)
	binary.BigEndian.PutUint32(pattern, packetID)

	pos := 0
	out := make([]byte, length)
	for pos < length {
		//copy from pos,
		copyLength := len(pattern)
		copyEndPos := pos + copyLength
		if copyEndPos > length {
			copyEndPos = length
			copyLength = copyEndPos - pos
		}
		copy(out[pos:copyEndPos], pattern[0:copyLength])
		pos = copyEndPos
	}

	return out
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
