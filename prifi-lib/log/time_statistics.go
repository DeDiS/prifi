package log

import (
	"fmt"
	"time"

	"gopkg.in/dedis/onet.v1/log"
)

//This class hold latencies values, and performs the average/std distribution of it. That is the max number of value stored.
const MAX_LATENCY_STORED = 100

//LatencyStatistics holds the latencies reported
type TimeStatistics struct {
	begin            time.Time
	nextReport       time.Time
	period           time.Duration
	reportNo         int
	totalValuesAdded int

	times []int64
}

//NewLatencyStatistics create a new LatencyStatistics struct, with a period (for reporting) of 5 second
func NewTimeStatistics() *TimeStatistics {
	fiveSec := time.Duration(5) * time.Second
	now := time.Now()
	stats := TimeStatistics{
		begin:            now,
		nextReport:       now,
		period:           fiveSec,
		reportNo:         0,
		totalValuesAdded: 0,
		times:            make([]int64, 0)}
	return &stats
}

//LatencyStatistics returns a triplet (mean, variance, number of samples) as formatted strings (2-digit precision)
func (stats *TimeStatistics) TimeStatistics() (string, string, string) {

	if len(stats.times) == 0 {
		return "-1", "-1", "-1"
	}

	m := RoundWithPrecision(MeanInt64(stats.times), 2)
	v := RoundWithPrecision(ConfidenceInterval95(stats.times), 2)

	return fmt.Sprintf("%v", m), fmt.Sprintf("%v", v), fmt.Sprintf("%v", len(stats.times))
}

//AddLatency adds a latency to the stored latency array, and removes the oldest one if there are more than MAX_LATENCY_STORED
func (stats *TimeStatistics) AddTime(latency int64) {
	stats.times = append(stats.times, latency)
	stats.totalValuesAdded++

	//we remove the first items
	if len(stats.times) > MAX_LATENCY_STORED {
		start := len(stats.times) - MAX_LATENCY_STORED
		stats.times = stats.times[start:]
	}
}

//Report prints (if t>period=5 seconds have passed since the last report) all the information, without extra data
func (stats *TimeStatistics) Report() string {
	return stats.ReportWithInfo("")
}

//ReportWithInfo prints (if t>period=5 seconds have passed since the last report) all the information, with extra data
func (stats *TimeStatistics) ReportWithInfo(info string) string {
	now := time.Now()
	if now.After(stats.nextReport) {

		mean, variance, n := stats.TimeStatistics()

		//human-readable output
		str := fmt.Sprintf("[%v] %s ms +- %s (over %s, happened %v). Info: %s", stats.reportNo, mean, variance, n, stats.totalValuesAdded, info)

		log.Lvl1(str)

		//json output
		strJSON := fmt.Sprintf("{ \"type\"=\"relay_timings\", \"report_id\"=\"%v\", \"duration_mean_ms\"=\"%s\", \"duration_dev_ms\"=\"%s\", \"mean_over\"=\"%s\", \"total_pop\"=\"%v\", \"info\"=\"%s\" }\n",
			stats.reportNo, mean, variance, n, stats.totalValuesAdded, info)

		//report to website
		data := fmt.Sprintf("no=%v&mean=%s&var=%s&n=%s&happened=%v&info=%s", stats.reportNo, mean, variance, n, stats.totalValuesAdded, info)

		_ = data
		//go performGETRequest("http://prifi.net/reporting/?" + data)

		stats.nextReport = now.Add(stats.period)
		stats.reportNo++

		return strJSON
	}
	return ""
}
