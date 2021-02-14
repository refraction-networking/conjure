package main

import "fmt"

// DetectorStats tracks numerical stats per period as seen by the station. These
// should be fairly straight-forward on a single threaded station
type DetectorStats struct {
	V6PacketCount uint64
	V4PacketCount uint64
	BytesTotal    uint64
	BytesV4       uint64
	BytesV6       uint64

	PacketsForwarded uint64

	// tot_sys_us
	// tot_usr_us
}

// Report returns a string summary of tracked stat
func (cds *DetectorStats) Report() string {

	return fmt.Sprintf("%d, %d, %d, %d, %d, %d",
		cds.V4PacketCount,
		cds.V6PacketCount,
		cds.BytesTotal,
		cds.BytesV4,
		cds.BytesV6,
		cds.PacketsForwarded)

}

// Reset sets all stat counters back to 0
func (cds *DetectorStats) Reset() {
	cds.V4PacketCount = 0
	cds.V6PacketCount = 0
	cds.BytesTotal = 0
	cds.BytesV4 = 0
	cds.BytesV6 = 0

	cds.PacketsForwarded = 0

	// tot_sys_us
	// tot_usr_us
}
