package detector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectorConfigBasics(t *testing.T) {
	os.Setenv("CJ_STATION_CONFIG", "./test/config.toml")

	conf, err := GetConfig()
	if err != nil {
		t.Fatalf("failed to parse app config: %v", err)
	}

	require.NotNil(t, conf)
	assert.Contains(t, conf.FilterList, "127.0.0.1")
	assert.Contains(t, conf.Tags, "nginx")
	assert.Equal(t, 3, conf.StatsFrequency)
	assert.Equal(t, 3, conf.CleanupFrequency)

	require.NotNil(t, conf.Source)
	assert.Equal(t, DataSourcePCAP, conf.Source.DataSourceType)
	assert.Contains(t, conf.Source.OfflinePcapPath, "min.pcap")
	assert.Equal(t, int32(1600), conf.Source.SnapLen)
	assert.Equal(t, uint64(100), conf.Source.NumPackets)
}
