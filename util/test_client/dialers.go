package main

import (
	"context"
	"net"

	"github.com/refraction-networking/gotapdance/tapdance"
	// tapdance1_2_0 "github.com/refraction-networking/gotapdance/v1-2-0/tapdance"
	// tapdance1_3_5 "github.com/refraction-networking/gotapdance/v1-3-5/tapdance"
	// tapdance1_5_6 "github.com/refraction-networking/gotapdance/v1-5-6/tapdance"
	// tapdance1_6_2 "github.com/refraction-networking/gotapdance/v1-6-2/tapdance"
)

type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var availableVersions = []string{
	"latest",
}

var availableDialers = map[string]dialer{
	"latest": &tapdance.Dialer{},
	// "v1.2.0": &tapdance1_2_0.Dialer{},
	// "v1.3.5": &tapdance1_3_5.Dialer{},
	// "v1.5.6": &tapdance1_5_6.Dialer{},
	// "v1.6.2": &tapdance1_6_2.Dialer{},
}
