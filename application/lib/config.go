package lib

import (
	"fmt"
	"net"
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

	// isthe station capable of handling v4 / v6 with independent toggles. 
	EnableIPv4 bool `toml:"enable_v4"`
	EnableIPv6 bool  `toml:"enable_v6"`

	// List of subnets with disallowed covert addresses.
	CovertBlocklist []string `toml:"covert_blocklist"`
	covertBlocklist []*net.IPNet
}

func ParseConfig() (*Config, error) {
	var c Config
	_, err := toml.DecodeFile(os.Getenv("CJ_STATION_CONFIG"), &c)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	c.covertBlocklist = []*net.IPNet{}
	for _, subnet := range c.CovertBlocklist {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			continue
		}

		c.covertBlocklist = append(c.covertBlocklist, ipNet)
	}

	return &c, nil
}

func (c *Config) IsBlocklisted(addr net.IP) bool {
	if addr == nil {
		return true
	}
	for _, subnet := range c.covertBlocklist {
		if subnet.Contains(addr) {
			return true
		}
	}
	return false
}
