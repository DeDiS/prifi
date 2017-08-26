package utils

import (
	"encoding/binary"
	"errors"
	"github.com/Lukasa/gopcap"
	"gopkg.in/dedis/onet.v1/log"
	"math/rand"
	"os"
)

const pattern uint16 = uint16(21845) //0101010101010101
const metaMessageLength int = 15     // 2bytes pattern + 4bytes ID + 8bytes timeStamp + 1 bit fragmentation

// Packet is an ID(Packet number), TimeSent in microsecond, and some Data
type Packet struct {
	ID                        uint32
	MsSinceBeginningOfCapture uint64 //milliseconds since beginning of capture
	Header                    []byte
	RealLength                int
}

// Parses a .pcap file, and returns all valid packets. A packet is (ID, TimeSent [micros], Data)
func ParsePCAP(path string, maxPayloadLength int) ([]Packet, error) {
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

		t := uint64((pkt.Timestamp.Nanoseconds() - timeDelta) / 1000000)
		remainingLen := int(pkt.IncludedLen)

		//maybe this packet is bigger than the payloadlength. Then, generate many packets
		for remainingLen > maxPayloadLength {
			p2 := Packet{
				ID:     uint32(id),
				Header: metaBytes(maxPayloadLength, uint32(id), t, false),
				MsSinceBeginningOfCapture: t,
				RealLength:                maxPayloadLength,
			}
			out = append(out, p2)
			remainingLen -= maxPayloadLength
		}

		//add the last packet, that will trigger the relay pattern match
		if remainingLen < metaMessageLength {
			remainingLen = metaMessageLength
		}
		p := Packet{
			ID:     uint32(id),
			Header: metaBytes(remainingLen, uint32(id), t, true),
			MsSinceBeginningOfCapture: t,
			RealLength:                remainingLen,
		}
		out = append(out, p)
	}

	return out, nil
}

func getPayloadOrRandom(pkt gopcap.Packet, packetID uint32, msSinceBeginningOfCapture uint64) []byte {
	len := pkt.IncludedLen

	if true || pkt.Data == nil {
		return metaBytes(int(len), packetID, msSinceBeginningOfCapture, false)
	}

	return pkt.Data.LinkData().InternetData().TransportData()
}

func metaBytes(length int, packetID uint32, timeSentInPcap uint64, isFinalPacket bool) []byte {
	// ignore length, have short messages
	if false && length < metaMessageLength {
		return recognizableBytes(length, packetID)
	}
	// out := make([]byte, length)
	out := make([]byte, 15)
	binary.BigEndian.PutUint16(out[0:2], pattern)
	binary.BigEndian.PutUint32(out[2:6], packetID)
	binary.BigEndian.PutUint64(out[6:14], timeSentInPcap)
	out[14] = byte(0)
	if isFinalPacket {
		out[14] = byte(1)
	}
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
