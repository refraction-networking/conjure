package station

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/refraction-networking/conjure/pkg/station/connection"
	"github.com/refraction-networking/conjure/pkg/station/lib"
)

// Config - Station golang configuration struct
type Config struct {
	*lib.ZMQConfig
	*lib.RegConfig
	*connection.ConnManagerConfig

	// Log verbosity level
	LogLevel    string `toml:"log_level"`
	LogClientIP bool   `toml:"log_client_ip"` // also available from the CJ_LOG_CLIENT_IP environment variable

	// Path to private key file
	PrivateKeyPath string `toml:"privkey_path"`

	// PrefixFilePath provides a path to a file containing supported prefix specifications for the
	// prefix transport.
	// [TODO] refactor into a more general transport config object
	PrefixFilePath         string `toml:"supplemental_prefix_path"`
	DisableDefaultPrefixes bool   `toml:"disable_default_prefixes"`
}

// ConfigFromEnv parses the config from the CJ_STATION_CONFIG environment variable.
func ConfigFromEnv() (*Config, error) {
	var envPath = os.Getenv("CJ_STATION_CONFIG")
	return ParseConfig(envPath)
}

// ParseConfig parses the config from the given path.
func ParseConfig(path string) (*Config, error) {
	var c Config
	_, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, fmt.Errorf("failed to load config (%s): %v", path, err)
	}

	c.RegConfig.ParseBlocklists()

	return &c, nil
}

// ParsePrivateKey tries to use either the PrivateKeyPath (`privkey_path`) config variable or the
// CJ_PRIVKEY environment variable to locate the file from which it can parse the station private key
func (c *Config) ParsePrivateKey() ([32]byte, error) {
	privkeyPath := c.PrivateKeyPath
	if privkeyPath == "" {
		privkeyPath = os.Getenv("CJ_PRIVKEY")
	}
	if privkeyPath == "" {
		return [32]byte{}, fmt.Errorf("no path to private key")
	}

	privkey, err := os.ReadFile(privkeyPath)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to load private key: %w", err)
	}

	if len(privkey) < PrivateKeyLength {
		return [32]byte{}, fmt.Errorf("privkey error - not enough bytes")
	}

	var out [32]byte
	copy(out[:], privkey[:])
	return out, nil
}
