package lib

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config - Station golang configuration struct
type Config struct {
	*ZMQConfig
	*RegConfig

	// Log verbosity level
	LogLevel string `toml:"log_level"`
}

// ParseConfig parses the config from the CJ_STATION_CONFIG environment
// variable.
func ParseConfig() (*Config, error) {
	var c Config
	_, err := toml.DecodeFile(os.Getenv("CJ_STATION_CONFIG"), &c)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	c.ParseBlocklists()

	return &c, nil
}
