package relay

import (
	"bytes"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/log"
	"testing"
)

/*
 * What we need to test:
 * - Can open several rounds; eg, open rounds 0, 1, 2, 3
 * - Round ID is always the smallest open round
 * - Can buffer (and re-use) data from futur rounds
 * - Past and closed rounds have their data cleared
 * - When a round is closed, it prints the time spent in the round
 * - Ability to store a owner schedule; a owner slots can be closed in advance, then this owner does not get a slot
 * - Must be able to tell how much data we have in one round
 * - Must sent the rate limit correctly if enabled
 */

func TestOwnerSlots(test *testing.T) {

	window := 1
	nClients := 3
	nTrustees := 1
	b := NewBufferableRoundManager(nClients, nTrustees, window)

	if b.lastOwner != -1 {
		test.Error("LastOwner should start at -1")
	}

	if b.UpdateAndGetNextOwnerID() != 0 {
		test.Error("UpdateAndGetNextOwnerID should be at 0")
	}
	if b.lastOwner != 0 {
		test.Error("LastOwner should be at 0")
	}
	//asking twice should not change this of course
	if b.lastOwner != 0 {
		test.Error("LastOwner should be at 0")
	}

	if b.UpdateAndGetNextOwnerID() != 1 {
		test.Error("UpdateAndGetNextOwnerID should be at 1")
	}
	if b.lastOwner != 1 {
		test.Error("LastOwner should be at 1")
	}

	if b.UpdateAndGetNextOwnerID() != 2 {
		test.Error("UpdateAndGetNextOwnerID should be at 2")
	}
	if b.lastOwner != 2 {
		test.Error("LastOwner should be at 2")
	}

	if b.UpdateAndGetNextOwnerID() != 0 {
		test.Error("UpdateAndGetNextOwnerID should be at 0")
	}
	if b.lastOwner != 0 {
		test.Error("LastOwner should be at 0")
	}

	//relay sends an OC slot request
	//client 0 and 2 reserve
	schedule := make(map[int]bool)
	schedule[0] = true
	schedule[1] = false
	schedule[2] = true
	//non-specified are false/closed by definition

	b.SetStoredRoundSchedule(schedule)
	//this should reset the ownership map

	if b.UpdateAndGetNextOwnerID() != 0 {
		test.Error("UpdateAndGetNextOwnerID should be at 0")
	}
	if b.lastOwner != 0 {
		test.Error("LastOwner should be at 0")
	}

	//client 1 does not want to communicate, should be client 2
	if b.UpdateAndGetNextOwnerID() != 2 {
		test.Error("UpdateAndGetNextOwnerID should be at 2")
	}
	if b.lastOwner != 2 {
		test.Error("LastOwner should be at 2")
	}

	//client 0 again
	if b.UpdateAndGetNextOwnerID() != 0 {
		test.Error("UpdateAndGetNextOwnerID should be at 0")
	}
	if b.lastOwner != 0 {
		test.Error("LastOwner should be at 0")
	}

	//client 1 does not want to communicate, should be client 2
	if b.UpdateAndGetNextOwnerID() != 2 {
		test.Error("UpdateAndGetNextOwnerID should be at 2")
	}
	if b.lastOwner != 2 {
		test.Error("LastOwner should be at 2")
	}
}

func TestRoundSuccessionWithSchedule(test *testing.T) {

	window := 10
	nClients := 1
	nTrustees := 1
	data := genDataSlice()
	b := NewBufferableRoundManager(nClients, nTrustees, window)

	b.OpenNextRound()

	if b.CurrentRound() != 0 {
		test.Error("Should be in round 0")
	}

	//requesting the next downstream round to send should not return an open round
	if b.NextRoundToOpen() != 1 {
		test.Error("NextRoundToOpen should be equal to 1", b.NextRoundToOpen())
	}
	//but should still return the same number
	if b.NextRoundToOpen() != 1 {
		test.Error("NextRoundToOpen should still be equal to 1", b.NextRoundToOpen())
	}

	//opening another round should not change current round
	b.OpenNextRound()
	if b.CurrentRound() != 0 {
		test.Error("Should be in round 0")
	}
	err := b.CloseRound()
	if err == nil {
		test.Error("Should not close round without the appropriate ciphers")
	}
	b.AddClientCipher(int32(0), 0, data)
	err = b.CloseRound()
	if err == nil {
		test.Error("Should not close round without the appropriate ciphers")
	}
	b.AddTrusteeCipher(int32(0), 0, data)
	err = b.CloseRound()
	if err != nil {
		test.Error("Should be able to close round")
	}

	if b.CurrentRound() != 1 {
		test.Error("Should be in round 1 now that round 0 was closed")
	}

	//requesting the next downstream round to send should not return an open round
	if b.NextRoundToOpen() != 2 {
		test.Error("NextRoundToOpen should be equal to 2", b.NextRoundToOpen())
	}

	//setting a round to closed should *not* skip it, only change ownership stuff
	s := make(map[int]bool, 2)
	s[2] = false
	s[4] = false
	b.SetStoredRoundSchedule(s)
	if b.storedOwnerSchedule == nil || len(b.storedOwnerSchedule) != len(s) || b.storedOwnerSchedule[0] != s[0] {
		test.Error("b.storedOwnerSchedule should be s")
	}
	if b.NextRoundToOpen() != 2 {
		test.Error("NextRoundToOpen should be equal to 2", b.NextRoundToOpen())
	}

	//should be able to open a round while skipping another round
	b.OpenNextRound() // round 2
	b.OpenNextRound() // round 3
	if b.CurrentRound() != 1 {
		test.Error("Should be in round 1")
	}
	b.AddClientCipher(int32(1), 0, data)
	b.AddTrusteeCipher(int32(1), 0, data)
	b.CloseRound() // 1
	if b.CurrentRound() != 2 {
		test.Error("Should be in round 2, but we're in round", b.CurrentRound())
	}
	b.AddClientCipher(int32(2), 0, data)
	b.AddTrusteeCipher(int32(2), 0, data)
	b.CloseRound()    // 2
	b.OpenNextRound() // 4
	if b.CurrentRound() != 3 {
		test.Error("Should be in round 3", b.CurrentRound())
	}

	if b.NextRoundToOpen() != 5 {
		test.Error("NextRoundToOpen should be equal to 5", b.NextRoundToOpen())
	}
}

func genDataSlice() []byte {
	return random.Bits(100, false, random.Stream)
}

func TestCipherBuffering(test *testing.T) {

	window := 10
	nClients := 1
	nTrustees := 1
	b := NewBufferableRoundManager(nClients, nTrustees, window)
	b.OpenNextRound()

	//check the initial state
	if b.CurrentRound() != 0 {
		test.Error("BufferManager should start in round 0")
	}
	if b.HasAllCiphersForCurrentRound() {
		test.Error("BufferManager does not have all ciphers yet, but claimed so")
	}
	c, t := b.MissingCiphersForCurrentRound()
	if len(c) != 1 || len(t) != 1 {
		test.Error("BufferManager did not compute correctly the missing ciphers")
	}
	err := b.CloseRound()
	if err == nil {
		test.Error("BufferManager should not be able to finalize round")
	}
	if b.NumberOfBufferedCiphers(0) != 0 {
		test.Error("Number of ciphers for trustee 0 should be 0")
	}

	clientSlice := genDataSlice()
	trusteeSlice := genDataSlice()

	//add a slice from a trustee
	b.AddTrusteeCipher(0, 0, trusteeSlice)

	if b.CurrentRound() != 0 {
		test.Error("BufferManager should still be in round 0")
	}
	if b.HasAllCiphersForCurrentRound() {
		test.Error("BufferManager does not have all ciphers yet, but claimed so")
	}
	c, t = b.MissingCiphersForCurrentRound()
	if len(c) != 1 || len(t) != 0 {
		test.Error("BufferManager did not compute correctly the missing ciphers")
	}
	if b.NumberOfBufferedCiphers(0) != 1 {
		test.Error("Number of ciphers for trustee 0 should be 1")
	}
	err = b.CloseRound()
	if err == nil {
		test.Error("BufferManager should not be able to finalize round")
	}
	if b.NumberOfBufferedCiphers(0) != 1 {
		test.Error("Number of ciphers for trustee 0 should be 1")
	}

	//add a slice from a client
	b.AddClientCipher(0, 0, clientSlice)

	if b.CurrentRound() != 0 {
		test.Error("BufferManager should still be in round 0")
	}
	if !b.HasAllCiphersForCurrentRound() {
		test.Error("BufferManager does have all ciphers")
	}
	c, t = b.MissingCiphersForCurrentRound()
	if len(c) != 0 || len(t) != 0 {
		test.Error("BufferManager did not compute correctly the missing ciphers")
	}
	clientSlices, trusteesSlices, err := b.CollectRoundData()
	if err != nil {
		test.Error("BufferManager should be able to finalize round")
	}
	err = b.CloseRound()
	if err != nil {
		test.Error("BufferManager should be able to finalize round")
	}
	if !bytes.Equal(clientSlices[0], clientSlice) {
		test.Error("Client slice should be the same")
	}
	if !bytes.Equal(trusteesSlices[0], trusteeSlice) {
		test.Error("Trustee slice should be the same")
	}

	b.OpenNextRound()

	//post round
	if b.NumberOfBufferedCiphers(0) != 0 {
		test.Error("Number of ciphers for trustee 0 should be 0")
	}
	if b.CurrentRound() != 1 {
		test.Error("BufferManager should now be in round 1, but is in round", b.CurrentRound())
	}
	if b.HasAllCiphersForCurrentRound() {
		test.Error("BufferManager does not have all ciphers for round 1")
	}
	c, t = b.MissingCiphersForCurrentRound()
	if len(c) != 1 || len(t) != 1 {
		test.Error("BufferManager did not compute correctly the missing ciphers")
	}

	clientSlice1 := genDataSlice()
	trusteeSlice1 := genDataSlice()
	clientSlice2 := genDataSlice()
	trusteeSlice2 := genDataSlice()
	trusteeSlice3 := genDataSlice()

	//should refuse to add slices in the apst
	if err = b.AddClientCipher(0, 0, clientSlice1); err == nil {
		test.Error("Should refuse to add client slices in the past")
	}
	if err = b.AddTrusteeCipher(0, 0, trusteeSlice1); err == nil {
		test.Error("Should refuse to add trustee slices in the past")
	}

	b.AddClientCipher(1, 0, clientSlice1)

	b.OpenNextRound() //round 2
	b.OpenNextRound() //round 3

	b.AddClientCipher(2, 0, clientSlice2)
	b.AddTrusteeCipher(3, 0, trusteeSlice3)

	//r1[c,]
	//r2[c,]
	//r3[,t]
	//nothing should have changed
	if b.CurrentRound() != 1 {
		test.Error("BufferManager should still be in round 1")
	}
	if b.HasAllCiphersForCurrentRound() {
		test.Error("BufferManager does not have all ciphers for round 1")
	}
	c, t = b.MissingCiphersForCurrentRound()
	if len(c) != 0 || len(t) != 1 {
		test.Error("BufferManager did not compute correctly the missing ciphers")
	}

	b.AddClientCipher(1, 0, clientSlice1)

	//r1[c,]
	//r2[c,]
	//r3[,t]
	//nothing should have changed if we re-add cipher 1 for client 0
	if b.CurrentRound() != 1 {
		test.Error("BufferManager should still be in round 1")
	}
	if b.HasAllCiphersForCurrentRound() {
		test.Error("BufferManager does not have all ciphers for round 1")
	}
	c, t = b.MissingCiphersForCurrentRound()
	if len(c) != 0 || len(t) != 1 {
		test.Error("BufferManager did not compute correctly the missing ciphers")
	}

	//r1[c,t]
	//r2[c,]
	//r3[,t]
	//add one trustee
	b.AddTrusteeCipher(1, 0, trusteeSlice1)
	clientSlices, trusteesSlices, err = b.CollectRoundData()
	if err != nil {
		test.Error("Should be able to finalize without error")
	}
	err = b.CloseRound()
	if err != nil {
		test.Error("Should be able to finalize without error")
	}
	if !bytes.Equal(clientSlices[0], clientSlice1) {
		test.Error("Client slice should be the same")
	}
	if !bytes.Equal(trusteesSlices[0], trusteeSlice1) {
		test.Error("Trustee slice should be the same")
	}

	//r2[c,]
	//r3[,t]
	//we should be in round 2, but already have the cipher for the client
	if b.CurrentRound() != 2 {
		test.Error("BufferManager should now be in round 2")
	}
	if b.HasAllCiphersForCurrentRound() {
		test.Error("BufferManager does not have all ciphers for round 2")
	}
	c, t = b.MissingCiphersForCurrentRound()
	if len(c) != 0 || len(t) != 1 {
		log.Error(b.CurrentRound(), b.trusteeAckMap, b.clientAckMap)
		test.Error("BufferManager did not compute correctly the missing ciphers")
	}

	//r2[c,t]
	//r3[,t]
	//add one trustee
	b.AddTrusteeCipher(2, 0, trusteeSlice2)
	clientSlices, trusteesSlices, err = b.CollectRoundData()
	if err != nil {
		test.Error("Should be able to finalize without error")
	}
	err = b.CloseRound()
	if err != nil {
		test.Error("Should be able to finalize without error")
	}
	if err != nil {
		test.Error("Should be able to finalize without error")
	}
	if !bytes.Equal(clientSlices[0], clientSlice2) {
		test.Error("Client slice should be the same")
	}
	if !bytes.Equal(trusteesSlices[0], trusteeSlice2) {
		test.Error("Trustee slice should be the same")
	}

	//r3[,t]
	//we should be in round 3 with one trustee
	if b.CurrentRound() != 3 {
		test.Error("BufferManager should now be in round 3")
	}
	if b.HasAllCiphersForCurrentRound() {
		test.Error("BufferManager does not have all ciphers for round 3")
	}
	c, t = b.MissingCiphersForCurrentRound()
	if len(c) != 1 || len(t) != 0 {
		test.Error("BufferManager did not compute correctly the missing ciphers")
	}

	//should both fail on nil slice
	err = b.AddClientCipher(0, 0, nil)
	if err == nil {
		test.Error("Shouldn't be able to add a nil slice")
	}
	err = b.AddTrusteeCipher(0, 0, nil)
	if err == nil {
		test.Error("Shouldn't be able to add a nil slice")
	}
}

func TestRateLimiter(test *testing.T) {

	window := 100
	nClients := 1
	nTrustees := 1
	b := NewBufferableRoundManager(nClients, nTrustees, window)

	low := 1  //resume sending when <= low
	high := 3 //stop sending when >= high

	stopCalled := false
	resumeCalled := false

	stopFn := func(int) {
		stopCalled = true
	}
	resFn := func(int) {
		resumeCalled = true
	}

	b.AddRateLimiter(low, high, stopFn, resFn)
	data := genDataSlice()

	b.OpenNextRound()
	b.AddTrusteeCipher(0, 0, data)
	if !resumeCalled {
		test.Error("Resume should have been called")
	}
	resumeCalled = false

	b.OpenNextRound()
	b.AddTrusteeCipher(1, 0, data)
	b.OpenNextRound()
	b.AddTrusteeCipher(2, 0, data)
	b.OpenNextRound()
	b.AddTrusteeCipher(3, 0, data)
	if !stopCalled {
		test.Error("Stop should have been called")
	}
	stopCalled = false
	b.OpenNextRound()
	b.AddTrusteeCipher(4, 0, data)
	if stopCalled {
		test.Error("Stop not should have been called again")
	}
	stopCalled = false

	b.AddClientCipher(0, 0, data)
	err := b.CloseRound()
	if err != nil {
		test.Error(err)
	}
	if stopCalled {
		test.Error("Stop not should have been called again (2)")
	}
	stopCalled = false

	b.AddClientCipher(1, 0, data)
	err = b.CloseRound()
	if err != nil {
		test.Error(err)
	}
	if stopCalled {
		test.Error("Stop not should have been called again (3)")
	}
	stopCalled = false
	b.AddClientCipher(2, 0, data)
	err = b.CloseRound()
	if err != nil {
		test.Error(err)
	}
	if stopCalled {
		test.Error("Stop should not have been called")
	}
	b.AddClientCipher(3, 0, data)
	err = b.CloseRound()
	if err != nil {
		test.Error(err)
	}

	if !resumeCalled {
		test.Error("Resume should have been called")
	}
}
