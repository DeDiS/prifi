package log

import (
	"testing"
)

func TestBWStatistics(t *testing.T) {
	b := NewBitRateStatistics(1500)
	b.AddDownstreamCell(int64(1000))
	b.AddDownstreamUDPCell(int64(2000), 2)
	b.AddDownstreamRetransmitCell(int64(1000))
	b.AddUpstreamCell(int64(1000))
	b.Report()
	b.Dump()
}
func TestLatencyStatistics(t *testing.T) {
	b := NewTimeStatistics()
	b.AddTime(int64(1000))
	b.AddTime(int64(2000))
	b.AddTime(int64(2000))
	b.Report()
}

func TestUtils(t *testing.T) {
	//round
	if Round(float64(6.3)) != 6 {
		t.Error("Rounding error")
	}
	if Round(float64(6.0)) != 6 {
		t.Error("Rounding error")
	}
	if Round(float64(6.5)) != 7 {
		t.Error("Rounding error")
	}

	//roundwithprecision
	if RoundWithPrecision(float64(6.3), 2) != 6.30 {
		t.Error("Rounding error")
	}
	if RoundWithPrecision(float64(6.125), 2) != 6.13 {
		t.Error("Rounding error")
	}
	if RoundWithPrecision(float64(6.41), 1) != 6.4 {
		t.Error("Rounding error")
	}

	//mean
	if MeanFloat64([]float64{1.2, 4.5, 6.9}) != 4.2 {
		t.Error("Rounding error")
	}

	//confidence interval
	delta := ConfidenceInterval95([]int64{30, 31, 29, 29, 35, 39, 26, 29})
	if RoundWithPrecision(delta, 2) != 2.66 {
		t.Error("ConfidenceInterval95 is wrong", delta, "!= 2.66")
	}

	err := performGETRequest("https://prifi.net")
	if err != nil {
		t.Error("Couldn't perform a GET request, err is", err.Error())
	}
}
