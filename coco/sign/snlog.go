package coco

import (
	"bytes"
	"encoding/gob"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/prifi/timestamp"
)

// Signing Node Log for a round
// For Marshaling and Unrmarshaling to work smoothly
// crypto fields must appear first in the structure
type SNLog struct {
	v     abstract.Secret // round lasting secret
	V     abstract.Point  // round lasting commitment point
	V_hat abstract.Point  // aggregate of commit points

	// merkle tree roots of children in strict order
	CMTRoots timestamp.HashId // concatenated hash ids of children
}

func (snLog SNLog) MarshalBinary() ([]byte, error) {
	// abstract.Write used to encode/ marshal crypto types
	b := bytes.Buffer{}
	abstract.Write(&b, &snLog.v, nist.NewAES128SHA256P256())
	abstract.Write(&b, &snLog.V, nist.NewAES128SHA256P256())
	abstract.Write(&b, &snLog.V_hat, nist.NewAES128SHA256P256())
	// gob is used to encode non-crypto types
	enc := gob.NewEncoder(&b)
	err := enc.Encode(snLog.CMTRoots)
	return b.Bytes(), err
}

func (snLog *SNLog) UnmarshalBinary(data []byte) error {
	// abstract.Read used to decode/ unmarshal crypto types
	b := bytes.NewBuffer(data)
	err := abstract.Read(b, snLog, nist.NewAES128SHA256P256())
	// gob is used to decode non-crypto types
	rem, _ := snLog.MarshalBinary()
	snLog.CMTRoots = data[len(rem):]
	return err
}
