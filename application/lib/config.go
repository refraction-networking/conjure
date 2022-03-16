package lib

import (
	"fmt"
	"net"
	"os"
	"regexp"

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
	EnableIPv6 bool `toml:"enable_v6"`

	// Local list of disallowed subnets for covert addresses.
	CovertBlocklistSubnets []string `toml:"covert_blocklist_subnets"`
	covertBlocklistSubnets []*net.IPNet

	// Local list of disallowed domain patterns for covert addresses.
	CovertBlocklistDomains []string `toml:"covert_blocklist_domains"`
	covertBlocklistDomains []*regexp.Regexp

	// Local list of disallowed subnets patterns for phantom addresses.
	PhantomBlocklist []string `toml:"phantom_blocklist"`
	phantomBlocklist []*net.IPNet

	// Expiration duration for cached live hosts
	CacheExpirationTime string `toml:"cache_expiration_time"`
}

func ParseConfig() (*Config, error) {
	var c Config
	_, err := toml.DecodeFile(os.Getenv("CJ_STATION_CONFIG"), &c)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	c.parseBlocklists()

	return &c, nil
}

func (c *Config) parseBlocklists() {
	c.covertBlocklistSubnets = []*net.IPNet{}
	for _, subnet := range c.CovertBlocklistSubnets {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err == nil {
			c.covertBlocklistSubnets = append(c.covertBlocklistSubnets, ipNet)
		}
	}

	c.covertBlocklistDomains = []*regexp.Regexp{}
	for _, r := range c.CovertBlocklistDomains {
		blockedDom := regexp.MustCompile(r)
		if blockedDom != nil {
			c.covertBlocklistDomains = append(c.covertBlocklistDomains, blockedDom)
		}
	}

	c.phantomBlocklist = []*net.IPNet{}
	for _, subnet := range c.PhantomBlocklist {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err == nil {
			c.phantomBlocklist = append(c.phantomBlocklist, ipNet)
		}
	}
}

func (c *Config) IsBlocklisted(urlStr string) bool {

	host, _, err := net.SplitHostPort(urlStr)
	if err != nil || host == "" {
		// unable to parse host:port
		return true
	}

	if addr := net.ParseIP(host); addr != nil {
		if !addr.IsGlobalUnicast() {
			// No anycast / private / loopback allowed.
			return true
		}
		for _, net := range c.covertBlocklistSubnets {
			if net.Contains(addr) {
				// blocked by IP address
				return true
			}
		}
	} else {
		for _, pattern := range c.covertBlocklistDomains {
			if pattern.MatchString(host) {
				// blocked by Domain pattern
				return true
			}
		}
	}
	return false
}

func (c *Config) IsBlocklistedPhantom(addr net.IP) bool {
	for _, net := range c.phantomBlocklist {
		if net.Contains(addr) {
			// blocked by IP address
			return true
		}
	}
	return false
}
