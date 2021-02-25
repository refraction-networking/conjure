package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectorConfigBasics(t *testing.T) {
	os.Setenv("CJ_STATION_CONFIG", "test/config.toml")

	conf, err := GetConfig()
	if err != nil {
		t.Fatalf("failed to parse app config: %v", err)
	}

	assert.NotNil(t, conf)
}
