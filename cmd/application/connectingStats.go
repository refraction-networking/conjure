package main

import (
	"fmt"
	"sync/atomic"

	cj "github.com/refraction-networking/conjure/pkg/station/lib"
)

var _ cj.ConnectingTpStats = &connStats{}

type connectingCounts struct {
	numCreatedConnecting               int64
	numCreatedToSuccessfulConnecting   int64
	numCreatedToFailedConnecting       int64
	numSuccessfulToDiscardedConnecting int64
}

func (c *connStats) AddCreatedConnecting(asn uint, cc string, tp string) {
	atomic.AddInt64(&c.numCreatedConnecting, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.geoIPMap[asn] = &asnCounts{}
			c.geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.geoIPMap[asn].numCreatedConnecting, 1)
	}
}

func (c *connStats) AddCreatedToSuccessfulConnecting(asn uint, cc string, tp string) {
	atomic.AddInt64(&c.numCreatedConnecting, -1)
	atomic.AddInt64(&c.numCreatedToSuccessfulConnecting, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.geoIPMap[asn] = &asnCounts{}
			c.geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.geoIPMap[asn].numCreatedConnecting, -1)
		atomic.AddInt64(&c.geoIPMap[asn].numCreatedToSuccessfulConnecting, 1)
	}
}

func (c *connStats) AddCreatedToFailedConnecting(asn uint, cc string, tp string, err error) {
	atomic.AddInt64(&c.numCreatedConnecting, -1)
	atomic.AddInt64(&c.numCreatedToFailedConnecting, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.geoIPMap[asn] = &asnCounts{}
			c.geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.geoIPMap[asn].numCreatedConnecting, -1)
		atomic.AddInt64(&c.geoIPMap[asn].numCreatedToFailedConnecting, 1)
	}
}

func (c *connStats) AddSuccessfulToDiscardedConnecting(asn uint, cc string, tp string) {
	atomic.AddInt64(&c.numCreatedToSuccessfulConnecting, -1)
	atomic.AddInt64(&c.numSuccessfulToDiscardedConnecting, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.geoIPMap[asn] = &asnCounts{}
			c.geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.geoIPMap[asn].numCreatedToSuccessfulConnecting, -1)
		atomic.AddInt64(&c.geoIPMap[asn].numSuccessfulToDiscardedConnecting, 1)
	}
}

func (c *connStats) resetConnecting() {
	c.connectingCounts = connectingCounts{}
}

func (c *connectingCounts) string() string {
	return fmt.Sprintf("%d %d %d %d ", atomic.LoadInt64(&c.numCreatedConnecting), atomic.LoadInt64(&c.numCreatedToSuccessfulConnecting), atomic.LoadInt64(&c.numCreatedToFailedConnecting), atomic.LoadInt64(&c.numSuccessfulToDiscardedConnecting))

}
