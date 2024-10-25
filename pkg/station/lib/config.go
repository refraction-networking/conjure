package lib

import (
	"fmt"
	"os"
	"path/filepath"

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

	// Path to ZMQ private key file
	ZMQPrivateKeyPath string `toml:"zmq_privkey_path"`

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

func (c *Config) ParseZMQPrivateKey() ([PrivateKeyLength]byte, error) {
	privkeyPath := c.ZMQPrivateKeyPath
	if privkeyPath == "" {
		privkeyPath = os.Getenv("ZMQ_PRIVKEY")
	}
	if privkeyPath == "" {
		return [PrivateKeyLength]byte{}, fmt.Errorf("no path to ZMQ private key")
	}

	return loadPrivateKey(privkeyPath)
}

// ParsePrivateKey tries to use either the PrivateKeyPath (`privkey_path`) config variable or the
// CJ_PRIVKEY environment variable to locate the file or directory containing the station private key(s).
func (c *Config) ParsePrivateKey() ([][PrivateKeyLength]byte, error) {
	privkeyPath := c.PrivateKeyPath
	if privkeyPath == "" {
		privkeyPath = os.Getenv("CJ_PRIVKEY")
	}
	if privkeyPath == "" {
		return nil, fmt.Errorf("no path to application private key")
	}

	fileInfo, err := os.Stat(privkeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access private key path: %w", err)
	}

	if fileInfo.IsDir() {
		files, err := os.ReadDir(privkeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}

		var keys [][PrivateKeyLength]byte

		for _, file := range files {
			if !file.IsDir() {
				key, err := loadPrivateKey(filepath.Join(privkeyPath, file.Name()))
				if err != nil {
					return nil, err
				}
				keys = append(keys, key)
			}
		}

		if len(keys) == 0 {
			return nil, fmt.Errorf("no valid keys found in directory")
		}

		return keys, nil
	}

	key, err := loadPrivateKey(privkeyPath)
	if err != nil {
		return nil, err
	}

	return [][PrivateKeyLength]byte{key}, nil
}

func loadPrivateKey(path string) ([32]byte, error) {
	privkey, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to load private key from %s: %w", path, err)
	}

	if len(privkey) < PrivateKeyLength {
		return [32]byte{}, fmt.Errorf("privkey error - not enough bytes in %s", path)
	}

	var out [PrivateKeyLength]byte
	copy(out[:], privkey[:])
	return out, nil
}
