package main

import (
	"fmt"
	"os"

	toml "github.com/pelletier/go-toml"
)

// Config defines the detector configuration including data plane specifics like
// packet source, and control plane information like tags, filter-lists,  and
// block-lists.
type Config struct {
	Source *DataSourceConfig
}

// GetConfig returns a Config parsed from the global environment var that
// defines the configuration location.
func GetConfig() (*Config, error) {
	return ParseConfig(os.Getenv("CJ_STATION_CONFIG"))
}

// ParseConfig parses a configuration file and a Config struct.
func ParseConfig(confPath string) (*Config, error) {
	var c Config

	_, err := toml.LoadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	return &c, nil
}
