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
	var envPath = os.Getenv("CJ_STATION_CONFIG")
	_, err := toml.DecodeFile(envPath, &c)
	if err != nil {
		return nil, fmt.Errorf("failed to load config (%s): %v", envPath, err)
	}

	c.ParseBlocklists()

	return &c, nil
}
