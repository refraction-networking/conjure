package lib

import (
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

	// t.Logf("%+v", conf)
	return
}
