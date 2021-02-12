package lib

import (
	"net"
	"os"
	"testing"
)

func TestConjureLibParseConfig(t *testing.T) {
	os.Setenv("CJ_STATION_CONFIG", "../config.toml")

	conf, err := ParseConfig()
	if err != nil {
		t.Fatalf("failed to parse app config: %v", err)
	}

	if len(conf.ZMQConfig.ConnectSockets) == 0 {
		t.Fatalf("No sockets provided to test parse")
	}

	if len(conf.covertBlocklistSubnets) == 0 {
		t.Fatalf("failed to parse blocklist")
	}
}

func TestConjureLibConfigBlocklists(t *testing.T) {

	conf := &Config{
		CovertBlocklistSubnets: []string{
			"192.0.0.1/16",
			"::1/128",
		},
		CovertBlocklistDomains: []string{
			".*blocked\\.com$",
			"blocked1\\.com",
			"localhost",
		},
	}

	conf.parseBlocklists()

	// Addresses that pass Blocklisted check
	goodURLs := []string{
		"[::2]:443",
		"blocked2.com:443",
		"127.0.0.1:443",
		"example.com:443",
		"192.255.0.22:domain",

		// These URLs will pass Blocklisted check, but fail at Dial("tcp", addr)
		"https://127.0.0.1",
		"https://example.com",
	}

	// Test Blocking
	blockedURLs := []string{
		"[::1]:443",
		"blocked.com:443",
		"abc.blocked.com:443",
		"blocked1.com:443",
		"192.0.2.1:http",
		"localhost:443",
	}

	// These urls will fail Blocklisted check (and also fail Dial("tcp", addr)).
	badURLs := []string{
		"https://::1",
		"https://[::1]:443",
		"127.0.0.1",
		"https://127.0.0.1:443",
		"example.com",
		"",
	}

	for _, s := range goodURLs {
		if conf.IsBlocklisted(s) {
			t.Fatalf("Blocklist error - %s should not be blocked", s)
		}
	}

	for _, s := range blockedURLs {
		if !conf.IsBlocklisted(s) {
			t.Fatalf("Blocklist error - %s should be blocked", s)
		}
	}

	for _, s := range badURLs {
		if !conf.IsBlocklisted(s) {
			t.Fatalf("Blocklist error - %s should fail (malformed)", s)
		}
	}
}

func TestConjureLibConfigBlocklistPhantoms(t *testing.T) {
	conf := &Config{
		PhantomBlocklist: []string{
			"192.168.0.0/16",
			"2001::0/64",
		},
	}

	conf.parseBlocklists()

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
