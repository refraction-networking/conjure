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

	// Path to private key file
	PrivateKeyPath string `toml:"privkey_path"`

	// PrefixFilePath provides a path to a file containing supported prefix specifications for the
	// prefix transport.
	// [TODO] refactor into a more general transport config object
	PrefixFilePath         string `toml:"supplemental_prefix_path"`
	DisableDefaultPrefixes bool   `toml:"disable_default_prefixes"`
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

// PrivateKeyLength is the expected length of the station (ed25519) private key in bytes.
const PrivateKeyLength = 32

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
