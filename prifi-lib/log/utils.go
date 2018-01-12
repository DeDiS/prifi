package log

import (
	"math"
	"net/http"
	"time"
)

//Round rounds up a float64, without digits after the comma
func Round(f float64) float64 {
	return math.Floor(f + .5)
}

//RoundWithPrecision rounds up a float64, with a specified amount of digits after the comma
func RoundWithPrecision(f float64, places int) float64 {
	shift := math.Pow(10, float64(places))
	return Round(f*shift) / shift
}

//MeanInt64 returns the mean for a []int64
func MeanInt64(data []int64) float64 {
	sum := int64(0)
	for i := 0; i < len(data); i++ {
		sum += data[i]
	}

	mean := float64(sum) / float64(len(data))
	return mean
}

//MeanFloat64 returns the mean for a []float64
func MeanFloat64(data []float64) float64 {
	sum := float64(0)
	for i := 0; i < len(data); i++ {
		sum += data[i]
	}

	mean := float64(sum) / float64(len(data))
	return mean
}

//Confidence95Percentiles returns the delta for the 95% confidence interval. The actual interval is [mean(x)-delta; mean(x)+delta]
func ConfidenceInterval95(data []int64) float64 {
	n := len(data)
	if n == 0 {
		return 0
	}
	mean_val := MeanInt64(data)

	var deviations []float64
	for i := 0; i < n; i++ {
		diff := mean_val - float64(data[i])
		deviations = append(deviations, diff*diff)
	}

	variance := MeanFloat64(deviations)
	stddev := math.Sqrt(variance)
	sigma := stddev / math.Sqrt(float64(n))
	z_value_95 := 1.96
	confidenceDelta := z_value_95 * sigma

	return confidenceDelta
}

//performGETRequest performs a GET request and ignores all errors
func performGETRequest(url string) error {
	_, err := http.Get(url)
	return err
}

// MsTimeStampNow returns the current timestamp, in milliseconds.
func MsTimeStampNow() int64 {
	return MsTimeStamp(time.Now())
}

// MsTimeStamp converts time.Time into int64
func MsTimeStamp(t time.Time) int64 {
	//http://stackoverflow.com/questions/24122821/go-golang-time-now-unixnano-convert-to-milliseconds
	return t.UnixNano() / int64(time.Millisecond)
}
