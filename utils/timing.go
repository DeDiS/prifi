// Package timing contains utility functions
// to measure execution times. It identifies measure
// by names to be able to start and stop the measurements
// from completely different parts of the code without
// having to share a variable.
//
// This package can be configured to use any
// object that implements the Output interface
// from the output package to write it's results.
package timing

import (
	"gopkg.in/dedis/onet.v1/log"
	"sync"
	"time"
)

var startTimes = make(map[string]time.Time)
var mutex sync.Mutex

// StartMeasure starts a time measure identified by a name.
func StartMeasure(name string) {
	mutex.Lock()

	if _, present := startTimes[name]; present {
		// Unlock before potentially expensive writing to output.
		mutex.Unlock()
		//log.Error("WARNING: starting a measure that already exists with name: ", name, " (nothing will happen)")
	} else {
		startTimes[name] = time.Now()
		mutex.Unlock()
	}
}

// StopMeasure stops a time measure identified by a name,
// prints the result to the current output interface and
// returns the measured time. Returns 0 if no measure was
// started with that name.
func StopMeasure(name string) time.Duration {
	// Store call time in case we have to wait for the mutex.
	now := time.Now()

	mutex.Lock()

	if start, ok := startTimes[name]; ok {
		duration := now.Sub(start)
		delete(startTimes, name)
		// Unlock before potentially expensive writing to output.
		mutex.Unlock()

		log.Lvl1("[timings] measured time for", name, ":", duration.Nanoseconds(), "ns")

		return duration
	}

	// Unlock before potentially expensive writing to output.
	mutex.Unlock()

	log.Lvl1("WARNING: stopping a measure that was not started with name: ", name)

	return time.Duration(0)
}
