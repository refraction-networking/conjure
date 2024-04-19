package detector

import (
	"fmt"
	"os"

	toml "github.com/pelletier/go-toml"
)

// Config defines the detector configuration including data plane specifics like
// packet source, and control plane information like tags, filter-lists,  and
// block-lists.
type Config struct {
	Source *DataSourceConfig `toml:"source"`

	// List of addresses to filter packets from (i.e. liveness testing)
	FilterList []string `toml:"filter_list"`

	// Tags checked for routing investigation purposes.
	Tags []string `toml:"detector_tags"`

	// Workers dictates the number of goroutines over which to balance packet handling
	Workers int `toml:"detector_workers"`

	// How often to log periodic statistics
	StatsFrequency int `toml:"stats_frequency"`

	// How often to run tracker cleanup
	CleanupFrequency int `toml:"cleanup_frequency"`
}

// GetConfig returns a Config parsed from the global environment var that
// defines the configuration location.
func GetConfig() (*Config, error) {
	return ParseConfig(os.Getenv("CJ_STATION_CONFIG"))
}

// ParseConfig parses a configuration file and a Config struct.
func ParseConfig(confPath string) (*Config, error) {
	var c Config

	tomlFile, err := toml.LoadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	err = tomlFile.Unmarshal(&c)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	return &c, nil
}
