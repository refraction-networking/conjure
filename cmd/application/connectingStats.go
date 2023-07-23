package main

import (
	"fmt"
	"sync/atomic"

	cj "github.com/refraction-networking/conjure/pkg/station/lib"
)

var _ cj.ConnectingTpStats = &connStats{}

type connectingCounts struct {
	numCreatedConnecting    int64
	numSuccessfulConnecting int64
	numFailedConnecting     int64
	numAuthFail             int64
	numOtherFail            int64
}

func (c *connStats) AddCreatedConnecting(asn uint, cc string, tp string) {
	atomic.AddInt64(&c.numCreatedConnecting, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.v4geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.v4geoIPMap[asn] = &asnCounts{}
			c.v4geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedConnecting, 1)
	}
}

func (c *connStats) AddCreatedToSuccessfulConnecting(asn uint, cc string, tp string) {
	atomic.AddInt64(&c.numCreatedConnecting, -1)
	atomic.AddInt64(&c.numSuccessfulConnecting, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.v4geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.v4geoIPMap[asn] = &asnCounts{}
			c.v4geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedConnecting, -1)
		atomic.AddInt64(&c.v4geoIPMap[asn].numSuccessfulConnecting, 1)
	}
}

func (c *connStats) AddCreatedToFailedConnecting(asn uint, cc string, tp string, err error) {
	atomic.AddInt64(&c.numCreatedConnecting, -1)
	atomic.AddInt64(&c.numFailedConnecting, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.v4geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.v4geoIPMap[asn] = &asnCounts{}
			c.v4geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedConnecting, -1)
		atomic.AddInt64(&c.v4geoIPMap[asn].numFailedConnecting, 1)
	}
}

func (c *connStats) AddSuccessfulToDiscardedConnecting(asn uint, cc string, tp string) {
}

func (c *connStats) AddAuthFailConnecting(asn uint, cc string, tp string) {
	atomic.AddInt64(&c.numAuthFail, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.v4geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.v4geoIPMap[asn] = &asnCounts{}
			c.v4geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.v4geoIPMap[asn].numAuthFail, 1)
	}

}

func (c *connStats) AddOtherFailConnecting(asn uint, cc string, tp string) {
	atomic.AddInt64(&c.numOtherFail, 1)

	if isValidCC(cc) {
		c.m.Lock()
		defer c.m.Unlock()
		if _, ok := c.v4geoIPMap[asn]; !ok {
			// We haven't seen asn before, so add it to the map
			c.v4geoIPMap[asn] = &asnCounts{}
			c.v4geoIPMap[asn].cc = cc
		}
		atomic.AddInt64(&c.v4geoIPMap[asn].numOtherFail, 1)
	}

}

func (c *connStats) resetConnecting() {
	c.connectingCounts = connectingCounts{}
}

func (c *connectingCounts) string() string {
	totalEndStates := atomic.LoadInt64(&c.numSuccessfulConnecting) + atomic.LoadInt64(&c.numFailedConnecting) + atomic.LoadInt64(&c.numAuthFail) + atomic.LoadInt64(&c.numOtherFail)
	if totalEndStates < 1 {
		totalEndStates = 0
	}
	return fmt.Sprintf("%d %d %d %d %d %.3f %.3f %.3f %.3f",
		atomic.LoadInt64(&c.numCreatedConnecting),
		atomic.LoadInt64(&c.numSuccessfulConnecting),
		atomic.LoadInt64(&c.numFailedConnecting),
		atomic.LoadInt64(&c.numAuthFail),
		atomic.LoadInt64(&c.numOtherFail),
		float64(atomic.LoadInt64(&c.numSuccessfulConnecting))/float64(totalEndStates),
		float64(atomic.LoadInt64(&c.numFailedConnecting))/float64(totalEndStates),
		float64(atomic.LoadInt64(&c.numAuthFail))/float64(totalEndStates),
		float64(atomic.LoadInt64(&c.numOtherFail))/float64(totalEndStates),
	)
}
