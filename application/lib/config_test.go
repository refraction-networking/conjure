package lib

import (
	"os"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

// TestConfigParse double checks to ensure that the identity struct reflection
// trick works and that the fields are accessible.
func TestConfigParse(t *testing.T) {
	os.Setenv("CJ_STATION_CONFIG", "../config.toml")

	var c Config
	_, err := toml.DecodeFile(os.Getenv("CJ_STATION_CONFIG"), &c)
	require.Nil(t, err)

	lc := c.LivenessConfig()
	require.NotEqual(t, "", lc.CacheDuration)
	require.NotEqual(t, "", lc.CacheDurationNonLive)

	// var db geoip.Database
	require.NotNil(t, c.RegConfig.DBConfig)
	// require.IsType(t, db, c.RegConfig.DBConfig)
}
