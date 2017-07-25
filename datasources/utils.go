package datasources

import "time"

// MsTimeStampNow returns the current timestamp, in milliseconds.
func MsTimeStampNow() int64 {
	return MsTimeStamp(time.Now())
}

// MsTimeStamp converts time.Time into int64
func MsTimeStamp(t time.Time) int64 {
	//http://stackoverflow.com/questions/24122821/go-golang-time-now-unixnano-convert-to-milliseconds
	return t.UnixNano() / int64(time.Millisecond)
}
