package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectorStatsBasics(t *testing.T) {
	var stats = &DetectorStats{}
	stats.Reset()
	require.Equal(t, uint64(0), stats.V4PacketCount)
	require.Equal(t, uint64(0), stats.V6PacketCount)
	require.Equal(t, uint64(0), stats.BytesTotal)
	require.Equal(t, uint64(0), stats.BytesV4)
	require.Equal(t, uint64(0), stats.BytesV6)
	require.Equal(t, uint64(0), stats.PacketsForwarded)

	report1 := stats.Report()
	require.Equal(t, "0, 0, 0, 0, 0, 0", report1)

	stats.V4PacketCount += 111
	stats.V6PacketCount += 222
	stats.BytesTotal += 333
	stats.BytesV4 += 444
	stats.BytesV6 += 555
	stats.PacketsForwarded += 666

	report2 := stats.Report()
	require.Equal(t, "111, 222, 333, 444, 555, 666", report2)
}
