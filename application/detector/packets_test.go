package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectorPacketsBasics(t *testing.T) {
	assert.Equal(t, 0, 1)
}

func TestDetectorPacketsFromPcap(t *testing.T) {
	// Parse pcap in `test/min.pcap`
	assert.Equal(t, 0, 1)
}

func TestDetectorPacketsIface(t *testing.T) {
	// Create temporary virtual interface using system
	// Listen on that interface and use tcpreplay to send packets from a pcap to
	// the interface to make sure interface listen works
	// - note: you will have to install tcpreplay from apt for this
	// - use pcap in `test/min.pcap`

	assert.Equal(t, 0, 1)
}
