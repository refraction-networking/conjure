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

	if len(conf.covertBlocklist) == 0 {
		t.Fatalf("failed to parse blocklist")
	}

	if !conf.IsBlocklisted(net.ParseIP("127.0.0.1")) {
		t.Fatalf("Blocklist error - 127.0.0.1 should be blocked")
	}

	if conf.IsBlocklisted(net.ParseIP("1.2.3.4")) {
		t.Fatalf("Blocklist error - 1.2.3.4 should not be blocked")
	}
}
