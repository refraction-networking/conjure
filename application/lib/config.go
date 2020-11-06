package lib

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config - Station golang configuration struct
type Config struct {
	ZMQConfig

	// Bool to enable or disable sharing of registrations over API when received over decoy registrar
	EnableShareOverAPI bool `toml:"enable_share_over_api"`

	// REST endpoint to share decoy registrations.
	PreshareEndpoint string `toml:"preshare_endpoint"`
}

func ParseConfig() (*Config, error) {
	var c *Config
	_, err := toml.DecodeFile(os.Getenv("CJ_STATION_CONFIG"), c)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	return c, nil
}
