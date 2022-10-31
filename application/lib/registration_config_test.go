package lib

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConjureLibConfigResolveBlocklisted(t *testing.T) {

	conf := &RegConfig{
		CovertBlocklistSubnets: []string{
			"192.0.0.1/16",
			"127.0.0.1/32",
			"::1/128",
		},
		CovertBlocklistDomains: []string{
			".*blocked\\.com$",
			"blocked1\\.com",
			"localhost",
		},
	}

	conf.ParseBlocklists()
	goodTestCases := map[string][]string{
		"128.0.2.1:25":     {"128.0.2.1:25"},
		"[2001:db8::1]:80": {"[2001:db8::1]:80"},
		"example.com:1234": {"93.184.216.34:1234", "[2606:2800:220:1:248:1893:25c8:1946]:1234"},
		"[::2]:443":        {"[::2]:443"},
	}

	for input, expected := range goodTestCases {
		output, _ := conf.ParseOrResolveBlocklisted(input)
		require.Contains(t, expected, output)
	}

	malformedTestCases := []string{
		"0.42.42.42",
		"192.0.2.1",
		"10.",
		"::1::1",
		".com:443",
		"192.255.0.22:domain",
		"192.255.0.22:100000",
		"http://example.com",
	}

	for _, input := range malformedTestCases {
		output, _ := conf.ParseOrResolveBlocklisted(input)
		require.Equal(t, "", output)
	}

	blocklistedTestCases := []string{
		"[::1]:443",
		"blocked.com:443",
		"abc.blocked.com:443",
		"blocked1.com:443",
		"192.0.2.1:http",
		"127.0.0.1:443",
		"localhost:443",
	}

	for _, input := range blocklistedTestCases {
		output, _ := conf.ParseOrResolveBlocklisted(input)
		require.Equal(t, "", output, "should be blocklisted")
	}
}

func TestConjureLibConfigBlocklistPhantoms(t *testing.T) {
	conf := &RegConfig{
		PhantomBlocklist: []string{
			"192.168.0.0/16",
			"2001::0/64",
		},
	}

	conf.ParseBlocklists()

	// Addresses that pass Blocklisted check
	goodIPs := []string{
		"[::2]",
		"127.0.0.1",
		"192.255.0.22",

		// These URLs will pass Blocklisted check, but fail at Dial("tcp", addr)
		"127.0.0.1",
		"192.0.0.0",
	}

	// Test Blocking
	blockedIPs := []string{
		"2001::abcd",
		"192.168.1.1",
	}

	for _, s := range goodIPs {
		addr := net.ParseIP(s)
		if conf.IsBlocklistedPhantom(addr) {
			t.Fatalf("Blocklist error - %s should not be blocked", s)
		}
	}

	for _, s := range blockedIPs {
		addr := net.ParseIP(s)
		if !conf.IsBlocklistedPhantom(addr) {
			t.Fatalf("Blocklist error - %s should be blocked", s)
		}
	}

}

func TestConjureLibConfigResolveAllowlisted(t *testing.T) {

	conf := &RegConfig{
		CovertAllowlistSubnets: []string{
			"128.138.0.1/16",
			"2001:db8::1/64",
		},
	}

	conf.ParseBlocklists()
	goodTestCases := map[string][]string{
		"128.138.2.1:25":   {"128.138.2.1:25"},
		"[2001:db8::1]:80": {"[2001:db8::1]:80"},
	}

	for input, expected := range goodTestCases {
		output, _ := conf.ParseOrResolveBlocklisted(input)
		require.Contains(t, expected, output)
	}

	blocklistedTestCases := []string{
		"[::1]:443",
		"blocked.com:443",
		"abc.blocked.com:443",
		"blocked1.com:443",
		"192.0.2.1:http",
		"127.0.0.1:443",
		"localhost:443",
	}

	for _, input := range blocklistedTestCases {
		output, _ := conf.ParseOrResolveBlocklisted(input)
		require.Equal(t, "", output, "should be blocklisted")
	}
}

func TestConjureLibConfigBlocklistPublic(t *testing.T) {
	conf := &RegConfig{
		CovertBlocklistPublicAddrs: true,
	}

	conf.ParseBlocklists()

	conf.ParseBlocklists()
	goodTestCases := map[string][]string{
		"128.138.2.1:25":   {"128.138.2.1:25"},
		"[2001:db8::1]:80": {"[2001:db8::1]:80"},
	}

	for input, expected := range goodTestCases {
		output, _ := conf.ParseOrResolveBlocklisted(input)
		require.Contains(t, expected, output)
	}

	blocklistedTestCases := []string{
		"[::1]:443",
		"127.0.0.1:443",
	}

	for _, input := range blocklistedTestCases {
		output, _ := conf.ParseOrResolveBlocklisted(input)
		require.Equal(t, "", output, "should be blocklisted")
	}
}

func TestConjureLibConfigResolveDidLookup(t *testing.T) {

	conf := &RegConfig{
		CovertBlocklistSubnets: []string{
			"192.0.0.1/16",
			"127.0.0.1/32",
			"::1/128",
		},
		CovertBlocklistDomains: []string{
			".*blocked\\.com$",
			"blocked1\\.com",
		},
	}

	conf.ParseBlocklists()

	testCases := map[string]bool{
		"[::1]:443":           false,
		"blocked.com:443":     false, // blocklist matches don't hit network
		"abc.blocked.com:443": false,
		"blocked1.com:443":    false,
		"blocked2.com:443":    true, // domains not explicitly blocklisted do resolve
		"192.0.2.1:http":      false,
		"127.0.0.1:443":       false,
		"localhost:443":       true, // this includes localhost (if not blocklisted)
	}

	for input, expected := range testCases {
		_, output := conf.ParseOrResolveBlocklisted(input)
		require.Equal(t, expected, output, input)
	}
}

func TestConjureLibConfigReload(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")

	conf1 := &RegConfig{
		CovertBlocklistSubnets: []string{
			"192.0.0.1/16",
			"127.0.0.1/32",
			"::1/128",
		},
		CovertBlocklistDomains: []string{
			".*blocked\\.com$",
			"blocked1\\.com",
		},
	}
	conf1.ParseBlocklists()

	conf2 := &RegConfig{
		CovertBlocklistDomains: []string{
			".*blocked\\.com$",
			"blocked1\\.com",
			"facebook\\.com",
		},
		enableCovertAllowlist: true,
		CovertAllowlistSubnets: []string{
			"127.0.0.1/32",
			"::1/128",
		},
	}
	conf2.ParseBlocklists()

	rm := NewRegistrationManager(conf1)
	require.NotNil(t, rm)
	require.Equal(t, 3, len(rm.covertBlocklistSubnets))
	require.False(t, rm.enableCovertAllowlist)
	require.Equal(t, 3, len(rm.PhantomSelector.Networks))

	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets_update.toml")

	rm.OnReload(conf2)
	require.True(t, rm.enableCovertAllowlist)
	require.Equal(t, 2, len(rm.covertAllowlistSubnets))
	require.Equal(t, 4, len(rm.PhantomSelector.Networks))
}
