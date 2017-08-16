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

		return duration
	}

	// Unlock before potentially expensive writing to output.
	mutex.Unlock()
	return time.Duration(0)
}

// StopMeasureAndLog prints the value to Lvl1 instead of returning it
func StopMeasureAndLog(name string) {
	duration := StopMeasure(name)
	log.Lvl1("[StopMeasureAndLog] measured time for", name, ":", duration.Nanoseconds(), "ns")
}

// StopMeasureAndLog prints the value to Lvl1 instead of returning it (logs "info" too)
func StopMeasureAndLogWithInfo(name, info string) {
	duration := StopMeasure(name)
	log.Lvl1("[StopMeasureAndLog] measured time for", name, ":", duration.Nanoseconds(), "ns, info:", info)
}
