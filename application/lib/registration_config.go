package lib

import (
	"net"
	"regexp"
	"strconv"

	"github.com/refraction-networking/conjure/application/geoip"
	"github.com/refraction-networking/conjure/application/liveness"
)

// RegConfig contains all configuration options directly related to processing
// registrations lifecycle (ingest, validity, and eviction).
type RegConfig struct {
	*liveness.Config
	*geoip.DBConfig

	// number of worker threads for ingesting incoming registrations.
	IngestWorkerCount int `toml:"ingest_worker_count"`

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
	// At launch add all public addresses from machine to blocklist.
	CovertBlocklistPublicAddrs bool `toml:"covert_blocklist_public_addrs"`
	// Local list of allowed subnets for covert addresses.
	CovertAllowlistSubnets []string `toml:"covert_allowlist_subnets"`
	enableCovertAllowlist  bool
	covertAllowlistSubnets []*net.IPNet

	// Local list of disallowed domain patterns for covert addresses.
	CovertBlocklistDomains []string `toml:"covert_blocklist_domains"`
	covertBlocklistDomains []*regexp.Regexp

	// Local list of disallowed subnets patterns for phantom addresses.
	PhantomBlocklist []string `toml:"phantom_blocklist"`
	phantomBlocklist []*net.IPNet
}

// ParseBlocklists converts string arrays of blocklisted domains, addresses and
// subnets and parses them into a usable format
func (c *RegConfig) ParseBlocklists() {
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

	c.covertAllowlistSubnets = []*net.IPNet{}
	for _, subnet := range c.CovertAllowlistSubnets {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err == nil {
			c.covertAllowlistSubnets = append(c.covertAllowlistSubnets, ipNet)
		}
	}
	if len(c.covertAllowlistSubnets) > 0 {
		c.enableCovertAllowlist = true
	}

	if c.CovertBlocklistPublicAddrs {
		// Add all public local addresses to the blocklist.
		ifaces, err := net.Interfaces()
		if err != nil {
			return
		}

		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					c.covertBlocklistSubnets = append(c.covertBlocklistSubnets, v)
				case *net.IPAddr:
					_, ipNet, err := net.ParseCIDR(v.IP.String() + "\\32")
					if err == nil {
						c.phantomBlocklist = append(c.phantomBlocklist, ipNet)
					}
				}

			}
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
// The bool return indicates whether the station resolved the domain name or not
func (c *RegConfig) ParseOrResolveBlocklisted(provided string) (string, bool) {

	a := net.ParseIP(provided)
	if a != nil {
		// IP address with no port provided
		return "", false
	}

	host, port, err := net.SplitHostPort(provided)
	if err != nil {
		return "", false
	}
	if c.isBlocklistedCovertDomain(host) {
		return "", false
	}

	_, err = strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", false
	}

	lookup := false
	if out := net.ParseIP(host); out == nil {
		lookup = true
	}

	addr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return "", lookup
	}
	if addr == nil || c.isBlocklistedCovertAddr(addr.IP) {
		return "", lookup
	}
	return net.JoinHostPort(addr.String(), port), lookup
}

// isBlocklistedCovertAddr checks if the provided host string should be
// blocked by on of the blocklisted subnets.
func (c *RegConfig) isBlocklistedCovertAddr(addr net.IP) bool {
	if c.enableCovertAllowlist {
		// If allowlist check is enabled it takes precedence over blocklist.
		for _, net := range c.covertAllowlistSubnets {
			if net.Contains(addr) {
				// blocked by IP address
				return false
			}
		}
		return true
	}

	for _, net := range c.covertBlocklistSubnets {
		if net.Contains(addr) {
			// blocked by IP address
			return true
		}
	}

	return false
}

// isBlocklistedCovertDomain checks if the provided host string should be
// blocked by on of the blocklisted Domain patterns.
func (c *RegConfig) isBlocklistedCovertDomain(provided string) bool {
	for _, pattern := range c.covertBlocklistDomains {
		if pattern.MatchString(provided) {
			return true
		}
	}

	return false
}

// IsBlocklistedPhantom checks if the provided address should be
// denied by on of the blocklisted Phantom subnets.
func (c *RegConfig) IsBlocklistedPhantom(addr net.IP) bool {
	for _, net := range c.phantomBlocklist {
		if net.Contains(addr) {
			// blocked by IP address
			return true
		}
	}
	return false
}
