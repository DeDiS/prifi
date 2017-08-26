package utils

import (
	"crypto/sha256"
	"math/big"
	"gopkg.in/dedis/crypto.v0/random"
)

var modulus = int64(123456789)

type Equivocation struct {
}

func Hash(b []byte) []byte {
	t := sha256.Sum256(b])
	return t[:]
}

// a function that takes a payload x, encrypt it as x' = x + k, and returns x' and kappa = k * history ^ (sum of the (hashes of pads))
func (e *Equivocation) ClientEncryptPayload(payload []byte, history []byte, pads [][]byte) ([]byte, []byte) {

	// modulus
	m := new(big.Int)
	m.SetInt64(modulus)

	// hash the pads
	hashOfPads := make([][]byte, len(pads))
	for k := range hashOfPads {
		hashOfPads[k] = Hash(pads[k])
	}

	// sum the hash
	sum := new(big.Int)
	for _, v := range hashOfPads {
		v2 := new(big.Int)
		v2.SetBytes(v)
		sum = sum.Add(sum, v2)
	}

	// raise the history to the sum
	h := new(big.Int)
	h.SetBytes(history)

	blindingFactor := new(big.Int)
	blindingFactor = blindingFactor.Exp(h, sum, m)

	// pick random key k
	k_bytes := random.Bits(uint(len(payload)), false, random.Stream)

	// encrypt payload
	for i := range k_bytes {
		payload[i] ^= k_bytes[i]
	}

	// compute kappa
	k := new(big.Int)
	k.SetBytes(k_bytes)

	kappa := new(big.Int)
	kappa = k.Mul(k, blindingFactor)

	kappa_bytes := kappa.Bytes()

	return payload, kappa_bytes
}

// a function that takes a payload x, encrypt it as x' = x + k, and returns x' and kappa = k * history ^ (sum of the (hashes of pads))
func (e *Equivocation) TrusteeGetContribution(pads [][]byte) ([]byte) {

	// modulus
	m := new(big.Int)
	m.SetInt64(modulus)

	// hash the pads
	hashOfPads := make([][]byte, len(pads))
	for k := range hashOfPads {
		hashOfPads[k] = Hash(pads[k])
	}

	// sum the hash
	sum := new(big.Int)
	for _, v := range hashOfPads {
		v2 := new(big.Int)
		v2.SetBytes(v)
		sum = sum.Add(sum, v2)
	}

	res := new(big.Int)
	res.SetInt64(int64(-1))
	res = res.Mul(res, sum)

	return res.Bytes()
}


func (e *Equivocation) RelayDecode(encryptedPayload []byte, history []byte, trusteesContributions [][]byte, clientsContributions [][]byte) []byte {

	// modulus
	m := new(big.Int)
	m.SetInt64(modulus)

	//reconstitute the bigInt values
	trusteesContrib := make([]big.Int, len(trusteesContributions))
	for k, v := range trusteesContributions {
		trusteesContrib[k] = new(big.Int)
		trusteesContrib[k].SetBytes(v)
	}
	clientsContrib := make([]big.Int, len(clientsContributions))
	for k, v := range clientsContributions {
		clientsContrib[k] = new(big.Int)
		clientsContrib[k].SetBytes(v)
	}

	h := new(big.Int)
	h.SetBytes(history)

	// compute sum of trustees contribs
	sum := new(big.Int)
	for _, v := range trusteesContrib {
		v2 := new(big.Int)
		v2.SetBytes(v)
		sum = sum.Add(sum, v2)
	}

	firstPart := h
	firstPart = firstPart.Exp(firstPart, sum, m)

	k := firstPart
	for _, v := range clientsContrib {
		k = k.Mul(k, v)
	}

	//now use k to decrypt the payload
	k_bytes := k.Bytes()
	for i := range k_bytes {
		encryptedPayload[i] ^= k_bytes[i]
	}

	return encryptedPayload
}