package log

import (
	"fmt"
	"time"

	"gopkg.in/dedis/onet.v1/log"
)

//BitrateStatistics holds statistics about the bitrate, such as instant/total up/down/down (via udp)/retransmitted bits
type BitrateStatistics struct {
	begin      time.Time
	nextReport time.Time
	period     time.Duration

	cellSize int

	totalUpstreamCells int64
	totalUpstreamBytes int64

	totalDownstreamCells int64
	totalDownstreamBytes int64

	instantUpstreamCells   int64
	instantUpstreamBytes   int64
	instantDownstreamBytes int64

	totalDownstreamUDPCells   int64
	totalDownstreamUDPBytes   int64
	instantDownstreamUDPBytes int64

	totalDownstreamRetransmitCells   int64
	totalDownstreamRetransmitBytes   int64
	instantDownstreamRetransmitBytes int64

	reportNo int
}

//NewBitRateStatistics create a new BitrateStatistics struct, with a period (for reporting) of 5 second
func NewBitRateStatistics(cellSize int) *BitrateStatistics {
	fiveSec := time.Duration(5) * time.Second
	now := time.Now()
	stats := BitrateStatistics{
		begin:      now,
		nextReport: now,
		reportNo:   0,
		period:     fiveSec,
		cellSize: cellSize}
	return &stats
}

// Dump prints all the contents of the BitrateStatistics
func (stats *BitrateStatistics) Dump() {
	log.Lvlf1("%+v\n", stats)
}

//AddDownstreamCell adds N bytes to the count of downstream bits
func (stats *BitrateStatistics) AddDownstreamCell(nBytes int64) {
	stats.totalDownstreamCells++
	stats.totalDownstreamBytes += nBytes
	stats.instantDownstreamBytes += nBytes
}

//AddDownstreamUDPCell adds N bytes to the count of downstream (via udp) bits
func (stats *BitrateStatistics) AddDownstreamUDPCell(nBytes int64, nclients int) {
	stats.totalDownstreamUDPCells++
	stats.totalDownstreamUDPBytes += nBytes
	stats.instantDownstreamUDPBytes += nBytes
}

//AddDownstreamRetransmitCell adds N bytes to the count of retransmitted bits
func (stats *BitrateStatistics) AddDownstreamRetransmitCell(nBytes int64) {
	stats.totalDownstreamRetransmitCells++
	stats.totalDownstreamRetransmitBytes += nBytes
	stats.instantDownstreamRetransmitBytes += nBytes
}

//AddUpstreamCell adds N bytes to the count of upstream bits
func (stats *BitrateStatistics) AddUpstreamCell(nBytes int64) {
	stats.totalUpstreamCells++
	stats.totalUpstreamBytes += nBytes
	stats.instantUpstreamCells++
	stats.instantUpstreamBytes += nBytes
}

//Report prints (if t>period=5 seconds have passed since the last report) all the information, without extra data
func (stats *BitrateStatistics) Report() string {
	return stats.ReportWithInfo("")
}

//ReportWithInfo prints (if t>period=5 seconds have passed since the last report) all the information, with extra data "info"
func (stats *BitrateStatistics) ReportWithInfo(info string) string {
	now := time.Now()
	if now.After(stats.nextReport) {

		//human-readable output
		str := fmt.Sprintf("[%v] %0.1f round/sec, %0.1f kB/s up, %0.1f kB/s down, %0.1f kB/s down(udp), %0.1f kB/s down(re-udp), %v cells, %v total",
			stats.reportNo,
			float64(stats.instantUpstreamCells)/stats.period.Seconds(),
			float64(stats.instantUpstreamBytes)/1024/stats.period.Seconds(),
			float64(stats.instantDownstreamBytes)/1024/stats.period.Seconds(),
			float64(stats.instantDownstreamUDPBytes)/1024/stats.period.Seconds(),
			float64(stats.instantDownstreamRetransmitBytes)/1024/stats.period.Seconds(),
			stats.totalUpstreamCells,
			int64(stats.totalUpstreamCells) * int64(stats.cellSize))

		log.Lvlf1(str)

		//json output
		strJSON := fmt.Sprintf("{ \"type\"=\"relay_bw\", \"report_id\"=\"%v\", \"round_per_sec\"=\"%0.1f\", \"up_kbps\"=\"%0.1f\", \"down_kbps\"=\"%0.1f\", \"down_udp_kbps\"=\"%0.1f\", \"down_re_udp_kbps\"=\"%0.1f\" }\n",
			stats.reportNo,
			float64(stats.instantUpstreamCells)/stats.period.Seconds(),
			float64(stats.instantUpstreamBytes)/1024/stats.period.Seconds(),
			float64(stats.instantDownstreamBytes)/1024/stats.period.Seconds(),
			float64(stats.instantDownstreamUDPBytes)/1024/stats.period.Seconds(),
			float64(stats.instantDownstreamRetransmitBytes)/1024/stats.period.Seconds())

		// Next report time
		stats.instantUpstreamCells = 0
		stats.instantUpstreamBytes = 0
		stats.instantDownstreamBytes = 0
		stats.instantDownstreamUDPBytes = 0
		stats.instantDownstreamRetransmitBytes = 0

		stats.nextReport = now.Add(stats.period)
		stats.reportNo++

		return strJSON
	}

	return ""
}
