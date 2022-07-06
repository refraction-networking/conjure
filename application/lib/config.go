package lib

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"

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

// ParseOrResolveBlocklisted attempts to return an IP:port string whenever
// possible either by parsing the IP to ensure correct format or resolving
// domain names. It also checks the configuration blocklists for both domain
// name and IP address. The intention of this function is that it be used to
// prevent SSRF DNS rebinding by doing resolution to final address to be used by
// net.Dial and checking blocklists in the same step.
//
// If a bad address / domain is given and empty string will be returned
func (c *Config) ParseOrResolveBlocklisted(provided string) string {

	a := net.ParseIP(provided)
	if a != nil {
		// IP address with no port provided
		return ""
	}

	host, port, err := net.SplitHostPort(provided)
	if err != nil {
		return ""
	}
	if c.isBlocklistedCovertDomain(host) {
		return ""
	}

	_, err = strconv.ParseUint(port, 10, 16)
	if err != nil {
		return ""
	}

	addr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return ""
	}
	if addr == nil || c.isBlocklistedCovertAddr(addr.IP) {
		return ""
	}
	return net.JoinHostPort(addr.String(), port)
}

// isBlocklistedCovertAddr checks if the provided host string should be
// blocked by on of the blocklisted subnets
func (c *Config) isBlocklistedCovertAddr(addr net.IP) bool {
	for _, net := range c.covertBlocklistSubnets {
		if net.Contains(addr) {
			// blocked by IP address
			return true
		}
	}

	return false
}

// isBlocklistedCovertDomain checks if the provided host string should be
// blocked by on of the blocklisted Domain patterns
func (c *Config) isBlocklistedCovertDomain(provided string) bool {
	for _, pattern := range c.covertBlocklistDomains {
		if pattern.MatchString(provided) {
			return true
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
