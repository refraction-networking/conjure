package geoip

import (
	"errors"
	"net"
)

var (
	// ErrNoDatabasesProvided indicates that no databases were provided so we are going to return a
	// struct implementing the Database interface so stations that don't support geoip can still
	// operate normally.
	ErrNoDatabasesProvided = errors.New("no databases provided - using empty Geoip")
)

// EmptyDatabase provides the Geoip functionality that we need using the MaxMind GeoIP service
type EmptyDatabase struct {
}

// ASN returns the Autonomous System Number (ASN) associated with the provided IP.
// The Empty Database Returns 0.
func (mmdb *EmptyDatabase) ASN(ip net.IP) (uint, error) {
	return 0, nil
}

// CC returns the ISO country code associated with the provided IP. The Empty Database Returns an
// empty string.
func (mmdb *EmptyDatabase) CC(ip net.IP) (string, error) {
	return "", nil
}
