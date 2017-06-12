package net

import (
	"encoding/binary"
	"errors"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
)

/*
 * Messages used by PriFi.
 * Syntax : SOURCE_DEST_CONTENT_CONTENT
 *
 * Below : Message-Switch that calls the correct function when one of this message arrives.
 */

// ALL_ALL_SHUTDOWN
// ALL_ALL_PARAMETERS
// CLI_REL_TELL_PK_AND_EPH_PK
// CLI_REL_UPSTREAM_DATA
// REL_CLI_DOWNSTREAM_DATA
// REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG
// REL_CLI_TELL_TRUSTEES_PK
// REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE
// REL_TRU_TELL_TRANSCRIPT
// TRU_REL_DC_CIPHER
// TRU_REL_SHUFFLE_SIG
// REL_TRU_TELL_RATE_CHANGE
// TRU_REL_TELL_NEW_BASE_AND_EPH_PKS
// TRU_REL_TELL_PK
// REL_TRU_TELL_RATE_CHANGE

//not used yet :
// REL_CLI_DOWNSTREAM_DATA
// CLI_REL_DOWNSTREAM_NACK

// ALL_ALL_SHUTDOWN message tells the participants to stop the protocol.
type ALL_ALL_SHUTDOWN struct {
}

// CLI_REL_TELL_PK_AND_EPH_PK message contains the public key and ephemeral key of a client
// and is sent to the relay.
type CLI_REL_TELL_PK_AND_EPH_PK struct {
	ClientID int
	Pk       abstract.Point
	EphPk    abstract.Point
}

// CLI_REL_UPSTREAM_DATA message contains the upstream data of a client for a given round
// and is sent to the relay.
type CLI_REL_UPSTREAM_DATA struct {
	ClientID int
	RoundID  int32
	Data     []byte
}

// CLI_REL_OPENCLOSED_DATA message contains whether slots are gonna be Open or Closed in the next round
type CLI_REL_OPENCLOSED_DATA struct {
	ClientID       int
	RoundID        int32
	OpenClosedData []byte
}

// REL_CLI_DOWNSTREAM_DATA message contains the downstream data for a client for a given round
// and is sent by the relay to the clients.
type REL_CLI_DOWNSTREAM_DATA struct {
	RoundID               int32
	Data                  []byte
	HashRoundID           int32
	Hash                  []byte
	FlagResync            bool
	FlagOpenClosedRequest bool
}

//Converts []ByteArray -> [][]byte and returns it
func (m *REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG) GetSignatures() [][]byte {
	out := make([][]byte, 0)
	for k := range m.TrusteesSigs {
		out = append(out, m.TrusteesSigs[k].Bytes)
	}
	return out
}

// REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG message contains the ephemeral public keys and the signatures
// of the trustees and is sent by the relay to the client.
type REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG struct {
	Base         abstract.Point
	EphPks       []abstract.Point
	TrusteesSigs []ByteArray
}

// REL_CLI_TELL_TRUSTEES_PK message contains the public keys of the trustees
// and is sent by the relay to the clients.
type REL_CLI_TELL_TRUSTEES_PK struct {
	Pks []abstract.Point
}

// REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE message contains the public keys and ephemeral keys
// of the clients and is sent by the relay to the trustees.
type REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE struct {
	Pks    []abstract.Point
	EphPks []abstract.Point
	Base   abstract.Point
}

//protobuf can't handle [][]abstract.Point, so we do []PublicKeyArray
type PublicKeyArray struct {
	Keys []abstract.Point
}

//protobuf can't handle [][]byte, so we do []ByteArray
type ByteArray struct {
	Bytes []byte
}

//Converts []PublicKeyArray -> [][]abstract.Point and returns it
func (m *REL_TRU_TELL_TRANSCRIPT) GetKeys() [][]abstract.Point {
	out := make([][]abstract.Point, 0)
	for k := range m.EphPks {
		out = append(out, m.EphPks[k].Keys)
	}
	return out
}

//Converts []ByteArray -> [][]byte and returns it
func (m *REL_TRU_TELL_TRANSCRIPT) GetProofs() [][]byte {
	out := make([][]byte, 0)
	for k := range m.Proofs {
		out = append(out, m.Proofs[k].Bytes)
	}
	return out
}

// REL_TRU_TELL_TRANSCRIPT message contains all the shuffles perfomrmed in a Neff shuffle round.
// It is sent by the relay to the trustees to be verified.
type REL_TRU_TELL_TRANSCRIPT struct {
	Bases  []abstract.Point
	EphPks []PublicKeyArray
	Proofs []ByteArray
}

// TRU_REL_DC_CIPHER message contains the DC-net cipher of a trustee for a given round and is sent to the relay.
type TRU_REL_DC_CIPHER struct {
	RoundID   int32
	TrusteeID int
	Data      []byte
}

// TRU_REL_SHUFFLE_SIG contains the signatures shuffled by a trustee and is sent to the relay.
type TRU_REL_SHUFFLE_SIG struct {
	TrusteeID int
	Sig       []byte
}

// REL_TRU_TELL_RATE_CHANGE message asks the trustees to update their window capacity to adapt their
// sending rate and is sent by the relay.
type REL_TRU_TELL_RATE_CHANGE struct {
	WindowCapacity int
}

// TRU_REL_TELL_NEW_BASE_AND_EPH_PKS message contains the new ephemeral key of a trustee and
// is sent to the relay.
type TRU_REL_TELL_NEW_BASE_AND_EPH_PKS struct {
	NewBase            abstract.Point
	NewEphPks          []abstract.Point
	Proof              []byte
	VerifiableDCNetKey []byte
}

// TRU_REL_TELL_PK message contains the public key of a trustee and is sent to the relay.
type TRU_REL_TELL_PK struct {
	TrusteeID int
	Pk        abstract.Point
}

// CLI_REL_QUERY contains a disrupted roundID and the public key of its owner, and is sent to the relay
type CLI_REL_QUERY struct {
	RoundID int32
	NIZK    []byte
	Pk      abstract.Point
}

// REL_CLI_QUERY contains a disrupted round's data encrypted for the owner, and is sent by the relay
type REL_CLI_QUERY struct {
	RoundID       int32
	EncryptedData abstract.Point
}

// CLI_REL_BLAME contains a disrupted roundID and the position where a bit was flipped, and is sent to the relay
type CLI_REL_BLAME struct {
	RoundID int32
	NIZK    []byte
	BitPos  int
}

// REL_ALL_REVEAL contains a disrupted roundID and the position where a bit was flipped, and is sent by the relay
type REL_ALL_REVEAL struct {
	RoundID int32
	BitPos  int
}

// CLI_REL_REVEAL contains a map with individual bits to find a disruptor, and is sent to the relay
type CLI_REL_REVEAL struct {
	ClientID int
	Bits     map[int]int
}

// TRU_REL_REVEAL contains a map with individual bits to find a disruptor, and is sent to the relay
type TRU_REL_REVEAL struct {
	TrusteeID int
	Bits      map[int]int
}

// REL_ALL_SECRET contains request ro reveal the shared secret with the specified recipient, and is sent by the relay
type REL_ALL_SECRET struct {
	UserID int
}

// CLI_REL_SECRET contains the shared secret requested by the relay, with a proof we computed it correctly
type CLI_REL_SECRET struct {
	Secret abstract.Point
	NIZK   []byte
}

// TRU_REL_SECRET contains the shared secret requested by the relay, with a proof we computed it correctly
type TRU_REL_SECRET struct {
	Secret abstract.Point
	NIZK   []byte
}

/*
REL_CLI_DOWNSTREAM_DATA_UDP message is a bit special. It's a REL_CLI_DOWNSTREAM_DATA, simply named with _UDP postfix to be able to distinguish them from type,
and theoretically that should be it. But since it doesn't go through SDA (which does not support UDP yet), we have to manually convert it to bytes.
For that purpose, this message implements MarshallableMessage, defined in prifi-sda-wrapper/udp.go.
Hence, it has methods Print(), used for debug, ToBytes(), that converts it to a raw byte array, SetByte(), which simply store a byte array in the
structure (but does not decode it), and FromBytes(), which decodes the REL_CLI_DOWNSTREAM_DATA from the inner buffer set by SetBytes()
*/
type REL_CLI_DOWNSTREAM_DATA_UDP struct {
	REL_CLI_DOWNSTREAM_DATA
}

// Print prints the raw value of this message.
func (m REL_CLI_DOWNSTREAM_DATA_UDP) Print() {
	log.Printf("%+v\n", m)
}

// SetBytes sets the bytes contained in this message.
func (m *REL_CLI_DOWNSTREAM_DATA_UDP) SetContent(data REL_CLI_DOWNSTREAM_DATA) {
	m.REL_CLI_DOWNSTREAM_DATA = data
}

// ToBytes encodes a message into a slice of bytes.
func (m *REL_CLI_DOWNSTREAM_DATA_UDP) ToBytes() ([]byte, error) {

	//convert the message to bytes
	buf := make([]byte, 4+len(m.REL_CLI_DOWNSTREAM_DATA.Data)+4+32+4+4)
	resyncInt := 0
	if m.REL_CLI_DOWNSTREAM_DATA.FlagResync {
		resyncInt = 1
	}
	openclosedInt := 0
	if m.REL_CLI_DOWNSTREAM_DATA.FlagOpenClosedRequest {
		openclosedInt = 1
	}

	// [0:4 roundID] [4:end-8 data] [end-8:end-4 resyncFlag] [end-4:end openClosedFlag]
	binary.BigEndian.PutUint32(buf[0:4], uint32(m.REL_CLI_DOWNSTREAM_DATA.RoundID))
	binary.BigEndian.PutUint32(buf[len(buf)-8:len(buf)-4], uint32(resyncInt)) //todo : to be coded on one byte
	binary.BigEndian.PutUint32(buf[len(buf)-4:], uint32(openclosedInt))       //todo : to be coded on one byte
	binary.BigEndian.PutUint32(buf[len(buf)-44:len(buf)-40], uint32(m.REL_CLI_DOWNSTREAM_DATA.HashRoundID))
	copy(buf[4:len(buf)-44], m.REL_CLI_DOWNSTREAM_DATA.Data)
	copy(buf[len(buf)-40:len(buf)-8], m.REL_CLI_DOWNSTREAM_DATA.Hash)

	return buf, nil

}

// FromBytes decodes the message contained in the message's byteEncoded field.
func (m *REL_CLI_DOWNSTREAM_DATA_UDP) FromBytes(buffer []byte) (interface{}, error) {

	//the smallest message is 4 bytes, indicating a length of 0
	if len(buffer) < 8 { //4 (roundID) + 4 (flagResync)
		e := "Messages.go : FromBytes() : cannot decode, smaller than 8 bytes"
		return REL_CLI_DOWNSTREAM_DATA_UDP{}, errors.New(e)
	}

	// [0:4 roundID] [4:end-8 data] [end-8:end-4 resyncFlag] [end-4:end openClosedFlag]
	roundID := int32(binary.BigEndian.Uint32(buffer[0:4]))
	hashRoundID := int32(binary.BigEndian.Uint32(buffer[len(buffer)-44 : len(buffer)-40]))
	flagResyncInt := int(binary.BigEndian.Uint32(buffer[len(buffer)-8 : len(buffer)-4]))
	flagOpenClosedInt := int(binary.BigEndian.Uint32(buffer[len(buffer)-4:]))
	data := buffer[4 : len(buffer)-44]
	hash := buffer[len(buffer)-40 : len(buffer)-8]

	flagResync := false
	if flagResyncInt == 1 {
		flagResync = true
	}
	flagOpenClosed := false
	if flagOpenClosedInt == 1 {
		flagOpenClosed = true
	}

	innerMessage := REL_CLI_DOWNSTREAM_DATA{roundID, data, hashRoundID, hash, flagResync, flagOpenClosed} //This wrapping feels weird
	resultMessage := REL_CLI_DOWNSTREAM_DATA_UDP{innerMessage}

	return resultMessage, nil
}
