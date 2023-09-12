package connection

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/conjure/pkg/log"
)

type statCounts struct {
	// States
	numCreated      int64 // Number of connections that have read 0 bytes so far
	numReading      int64 // Number of connections in the read / read more state trying to find reg that have read at least 1 byte
	numIODiscarding int64 // Number of connections in the io discard state
	numChecking     int64 // Number of connections that have taken a break from reading to check for the wrapping transport

	// Outcomes
	numFound   int64 // Number of connections that found their registration using wrapConnection
	numReset   int64 // Number of connections that received a reset while attempting to find registration
	numTimeout int64 // Number of connections that timed out while attempting to find registration
	numClosed  int64 // Number of connections that closed before finding the associated registration
	numErr     int64 // Number of connections that received an unexpected error

	// Transitions
	numCreatedToDiscard int64 // Number of times connections have moved from Created to Discard
	numCreatedToCheck   int64 // Number of times connections have moved from Created to Check
	numCreatedToReset   int64 // Number of times connections have moved from Created to Reset
	numCreatedToTimeout int64 // Number of times connections have moved from Created to Timeout
	numCreatedToError   int64 // Number of times connections have moved from Created to Error
	numCreatedToClose   int64 // Number of times connections have moved from Created to Closed

	numReadToCheck   int64 // Number of times connections have moved from Read to Check
	numReadToTimeout int64 // Number of times connections have moved from Read to Timeout
	numReadToReset   int64 // Number of times connections have moved from Read to Reset
	numReadToError   int64 // Number of times connections have moved from Read to Error

	numCheckToCreated int64 // Number of times connections have moved from Check to Created
	numCheckToRead    int64 // Number of times connections have moved from Check to Read
	numCheckToFound   int64 // Number of times connections have moved from Check to Found
	numCheckToError   int64 // Number of times connections have moved from Check to Error
	numCheckToDiscard int64 // Number of times connections have moved from Check to Discard

	numDiscardToReset   int64 // Number of times connections have moved from Discard to Reset
	numDiscardToTimeout int64 // Number of times connections have moved from Discard to Timeout
	numDiscardToError   int64 // Number of times connections have moved from Discard to Error
	numDiscardToClose   int64 // Number of times connections have moved from Discard to Close

	totalTransitions int64 // Number of all transitions tracked
	numNewConns      int64 // Number new connections potentially handshaking
	numResolved      int64 // Number connections that have reached a terminal state.

	connectingCounts
}

type asnCounts struct {
	cc string
	statCounts
}

type connStats struct {
	m          sync.RWMutex
	epochStart time.Time
	ipv4       statCounts
	ipv6       statCounts
	v4geoIPMap map[uint]*asnCounts
	v6geoIPMap map[uint]*asnCounts

	connectingCounts
}

func (c *connStats) PrintAndReset(logger *log.Logger) {
	c.m.Lock() // protect both read for print and write for reset.
	defer c.m.Unlock()

	// prevent div by 0 if thread starvation happens
	var epochDur float64 = math.Max(float64(time.Since(c.epochStart).Milliseconds()), 1)

	numASNs := 0
	if c.v4geoIPMap != nil {
		numASNs = len(c.v4geoIPMap)
	}

	if numASNs > 0 {
		logger.Infof("conn-stats (IPv4): %d %d %d %d %d %.3f %d %.3f %d %.3f %d %.3f %d %.3f %d %s",
			atomic.LoadInt64(&c.ipv4.numCreated),
			atomic.LoadInt64(&c.ipv4.numReading),
			atomic.LoadInt64(&c.ipv4.numChecking),
			atomic.LoadInt64(&c.ipv4.numIODiscarding),
			atomic.LoadInt64(&c.ipv4.numFound),
			1000*float64(atomic.LoadInt64(&c.ipv4.numFound))/epochDur,
			atomic.LoadInt64(&c.ipv4.numReset),
			1000*float64(atomic.LoadInt64(&c.ipv4.numReset))/epochDur,
			atomic.LoadInt64(&c.ipv4.numTimeout),
			1000*float64(atomic.LoadInt64(&c.ipv4.numTimeout))/epochDur,
			atomic.LoadInt64(&c.ipv4.numErr),
			1000*float64(atomic.LoadInt64(&c.ipv4.numErr))/epochDur,
			atomic.LoadInt64(&c.ipv4.numClosed),
			1000*float64(atomic.LoadInt64(&c.ipv4.numClosed))/epochDur,
			numASNs,
			c.connectingCounts.string(),
		)
	}

	numASNs = 0
	if c.v6geoIPMap != nil {
		numASNs = len(c.v6geoIPMap)
	}

	if numASNs > 0 {
		logger.Infof("conn-stats (IPv6): %d %d %d %d %d %.3f %d %.3f %d %.3f %d %.3f %d %.3f %d",
			atomic.LoadInt64(&c.ipv6.numCreated),
			atomic.LoadInt64(&c.ipv6.numReading),
			atomic.LoadInt64(&c.ipv6.numChecking),
			atomic.LoadInt64(&c.ipv6.numIODiscarding),
			atomic.LoadInt64(&c.ipv6.numFound),
			1000*float64(atomic.LoadInt64(&c.ipv6.numFound))/epochDur,
			atomic.LoadInt64(&c.ipv6.numReset),
			1000*float64(atomic.LoadInt64(&c.ipv6.numReset))/epochDur,
			atomic.LoadInt64(&c.ipv6.numTimeout),
			1000*float64(atomic.LoadInt64(&c.ipv6.numTimeout))/epochDur,
			atomic.LoadInt64(&c.ipv6.numErr),
			1000*float64(atomic.LoadInt64(&c.ipv6.numErr))/epochDur,
			atomic.LoadInt64(&c.ipv6.numClosed),
			1000*float64(atomic.LoadInt64(&c.ipv6.numClosed))/epochDur,
			numASNs,
		)
	}

	for i, val := range [2]map[uint]*asnCounts{c.v4geoIPMap, c.v6geoIPMap} {
		ip_ver := 4
		if i == 1 {
			ip_ver = 6
		}
		for asn, counts := range val {
			var tt = math.Max(1, float64(atomic.LoadInt64(&counts.totalTransitions)))
			logger.Infof("conn-stats-verbose (IPv%d): %d %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %d %d %d %d %s",
				ip_ver,
				asn,
				counts.cc,
				atomic.LoadInt64(&counts.numCreatedToDiscard),
				atomic.LoadInt64(&counts.numCreatedToCheck),
				atomic.LoadInt64(&counts.numCreatedToReset),
				atomic.LoadInt64(&counts.numCreatedToTimeout),
				atomic.LoadInt64(&counts.numCreatedToError),
				atomic.LoadInt64(&counts.numCreatedToClose),
				atomic.LoadInt64(&counts.numReadToCheck),
				atomic.LoadInt64(&counts.numReadToTimeout),
				atomic.LoadInt64(&counts.numReadToReset),
				atomic.LoadInt64(&counts.numReadToError),
				atomic.LoadInt64(&counts.numCheckToCreated),
				atomic.LoadInt64(&counts.numCheckToRead),
				atomic.LoadInt64(&counts.numCheckToFound),
				atomic.LoadInt64(&counts.numCheckToError),
				atomic.LoadInt64(&counts.numCheckToDiscard),
				atomic.LoadInt64(&counts.numDiscardToReset),
				atomic.LoadInt64(&counts.numDiscardToTimeout),
				atomic.LoadInt64(&counts.numDiscardToError),
				atomic.LoadInt64(&counts.numDiscardToClose),
				atomic.LoadInt64(&counts.totalTransitions),
				float64(atomic.LoadInt64(&counts.numCreatedToDiscard))/tt,
				float64(atomic.LoadInt64(&counts.numCreatedToCheck))/tt,
				float64(atomic.LoadInt64(&counts.numCreatedToReset))/tt,
				float64(atomic.LoadInt64(&counts.numCreatedToTimeout))/tt,
				float64(atomic.LoadInt64(&counts.numCreatedToError))/tt,
				float64(atomic.LoadInt64(&counts.numReadToCheck))/tt,
				float64(atomic.LoadInt64(&counts.numReadToTimeout))/tt,
				float64(atomic.LoadInt64(&counts.numReadToReset))/tt,
				float64(atomic.LoadInt64(&counts.numReadToError))/tt,
				float64(atomic.LoadInt64(&counts.numCheckToCreated))/tt,
				float64(atomic.LoadInt64(&counts.numCheckToRead))/tt,
				float64(atomic.LoadInt64(&counts.numCheckToFound))/tt,
				float64(atomic.LoadInt64(&counts.numCheckToError))/tt,
				float64(atomic.LoadInt64(&counts.numCheckToDiscard))/tt,
				float64(atomic.LoadInt64(&counts.numDiscardToReset))/tt,
				float64(atomic.LoadInt64(&counts.numDiscardToTimeout))/tt,
				float64(atomic.LoadInt64(&counts.numDiscardToError))/tt,
				float64(atomic.LoadInt64(&counts.numDiscardToClose))/tt,
				atomic.LoadInt64(&c.ipv6.numNewConns),
				atomic.LoadInt64(&counts.numNewConns),
				atomic.LoadInt64(&c.ipv6.numResolved),
				atomic.LoadInt64(&counts.numResolved),
				counts.connectingCounts.string(),
			)
		}
	}

	c.reset()
}

func (c *connStats) Reset() {
	c.m.Lock()
	defer c.m.Unlock()
	c.reset()
}

func (c *connStats) reset() {
	atomic.StoreInt64(&c.ipv4.numFound, 0)
	atomic.StoreInt64(&c.ipv4.numErr, 0)
	atomic.StoreInt64(&c.ipv4.numTimeout, 0)
	atomic.StoreInt64(&c.ipv4.numReset, 0)
	atomic.StoreInt64(&c.ipv4.numClosed, 0)
	atomic.StoreInt64(&c.ipv4.numCreatedToDiscard, 0)
	atomic.StoreInt64(&c.ipv4.numCreatedToCheck, 0)
	atomic.StoreInt64(&c.ipv4.numCreatedToReset, 0)
	atomic.StoreInt64(&c.ipv4.numCreatedToTimeout, 0)
	atomic.StoreInt64(&c.ipv4.numCreatedToError, 0)
	atomic.StoreInt64(&c.ipv4.numReadToCheck, 0)
	atomic.StoreInt64(&c.ipv4.numReadToTimeout, 0)
	atomic.StoreInt64(&c.ipv4.numReadToReset, 0)
	atomic.StoreInt64(&c.ipv4.numReadToError, 0)
	atomic.StoreInt64(&c.ipv4.numCheckToCreated, 0)
	atomic.StoreInt64(&c.ipv4.numCheckToRead, 0)
	atomic.StoreInt64(&c.ipv4.numCheckToFound, 0)
	atomic.StoreInt64(&c.ipv4.numCheckToError, 0)
	atomic.StoreInt64(&c.ipv4.numCheckToDiscard, 0)
	atomic.StoreInt64(&c.ipv4.numDiscardToReset, 0)
	atomic.StoreInt64(&c.ipv4.numDiscardToTimeout, 0)
	atomic.StoreInt64(&c.ipv4.numDiscardToError, 0)
	atomic.StoreInt64(&c.ipv4.numDiscardToClose, 0)
	atomic.StoreInt64(&c.ipv4.totalTransitions, 0)
	atomic.StoreInt64(&c.ipv4.numNewConns, 0)
	atomic.StoreInt64(&c.ipv4.numResolved, 0)

	atomic.StoreInt64(&c.ipv6.numFound, 0)
	atomic.StoreInt64(&c.ipv6.numErr, 0)
	atomic.StoreInt64(&c.ipv6.numTimeout, 0)
	atomic.StoreInt64(&c.ipv6.numReset, 0)
	atomic.StoreInt64(&c.ipv6.numClosed, 0)
	atomic.StoreInt64(&c.ipv6.numCreatedToDiscard, 0)
	atomic.StoreInt64(&c.ipv6.numCreatedToCheck, 0)
	atomic.StoreInt64(&c.ipv6.numCreatedToReset, 0)
	atomic.StoreInt64(&c.ipv6.numCreatedToTimeout, 0)
	atomic.StoreInt64(&c.ipv6.numCreatedToError, 0)
	atomic.StoreInt64(&c.ipv6.numReadToCheck, 0)
	atomic.StoreInt64(&c.ipv6.numReadToTimeout, 0)
	atomic.StoreInt64(&c.ipv6.numReadToReset, 0)
	atomic.StoreInt64(&c.ipv6.numReadToError, 0)
	atomic.StoreInt64(&c.ipv6.numCheckToCreated, 0)
	atomic.StoreInt64(&c.ipv6.numCheckToRead, 0)
	atomic.StoreInt64(&c.ipv6.numCheckToFound, 0)
	atomic.StoreInt64(&c.ipv6.numCheckToError, 0)
	atomic.StoreInt64(&c.ipv6.numCheckToDiscard, 0)
	atomic.StoreInt64(&c.ipv6.numDiscardToReset, 0)
	atomic.StoreInt64(&c.ipv6.numDiscardToTimeout, 0)
	atomic.StoreInt64(&c.ipv6.numDiscardToError, 0)
	atomic.StoreInt64(&c.ipv6.numDiscardToClose, 0)
	atomic.StoreInt64(&c.ipv6.totalTransitions, 0)
	atomic.StoreInt64(&c.ipv6.numNewConns, 0)
	atomic.StoreInt64(&c.ipv6.numResolved, 0)

	c.v4geoIPMap = make(map[uint]*asnCounts)
	c.v6geoIPMap = make(map[uint]*asnCounts)

	c.epochStart = time.Now()

	c.resetConnecting()
}

func (c *connStats) addCreated(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numCreated, 1)
		atomic.AddInt64(&c.ipv4.numNewConns, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreated, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numNewConns, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numCreated, 1)
		atomic.AddInt64(&c.ipv6.numNewConns, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreated, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numNewConns, 1)
		}
	}
}

func (c *connStats) createdToDiscard(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numCreated, -1)
		atomic.AddInt64(&c.ipv4.numIODiscarding, 1)
		atomic.AddInt64(&c.ipv4.numCreatedToDiscard, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numIODiscarding, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedToDiscard, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numCreated, -1)
		atomic.AddInt64(&c.ipv6.numIODiscarding, 1)
		atomic.AddInt64(&c.ipv6.numCreatedToDiscard, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numIODiscarding, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreatedToDiscard, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
		}
	}
}

func (c *connStats) createdToCheck(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numCreated, -1)
		atomic.AddInt64(&c.ipv4.numChecking, 1)
		atomic.AddInt64(&c.ipv4.numCreatedToCheck, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numChecking, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedToCheck, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numCreated, -1)
		atomic.AddInt64(&c.ipv6.numChecking, 1)
		atomic.AddInt64(&c.ipv6.numCreatedToCheck, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numChecking, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreatedToCheck, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
		}
	}
}

func (c *connStats) createdToReset(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numCreated, -1)
		atomic.AddInt64(&c.ipv4.numReset, 1)
		atomic.AddInt64(&c.ipv4.numCreatedToReset, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numReset, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedToReset, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numCreated, -1)
		atomic.AddInt64(&c.ipv6.numReset, 1)
		atomic.AddInt64(&c.ipv6.numCreatedToReset, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numReset, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreatedToReset, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) createdToTimeout(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numCreated, -1)
		atomic.AddInt64(&c.ipv4.numTimeout, 1)
		atomic.AddInt64(&c.ipv4.numCreatedToTimeout, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numTimeout, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedToTimeout, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numCreated, -1)
		atomic.AddInt64(&c.ipv6.numTimeout, 1)
		atomic.AddInt64(&c.ipv6.numCreatedToTimeout, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numTimeout, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreatedToTimeout, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) createdToError(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numCreated, -1)
		atomic.AddInt64(&c.ipv4.numErr, 1)
		atomic.AddInt64(&c.ipv4.numCreatedToError, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numErr, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedToError, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numCreated, -1)
		atomic.AddInt64(&c.ipv6.numErr, 1)
		atomic.AddInt64(&c.ipv6.numCreatedToError, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numErr, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreatedToError, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) createdToClose(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numCreated, -1)
		atomic.AddInt64(&c.ipv4.numClosed, 1)
		atomic.AddInt64(&c.ipv4.numCreatedToClose, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numClosed, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreatedToClose, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numCreated, -1)
		atomic.AddInt64(&c.ipv6.numClosed, 1)
		atomic.AddInt64(&c.ipv6.numCreatedToClose, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreated, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numClosed, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreatedToClose, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) readToCheck(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numReading, -1)
		atomic.AddInt64(&c.ipv4.numChecking, 1)
		atomic.AddInt64(&c.ipv4.numReadToCheck, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numReading, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numChecking, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numReadToCheck, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numReading, -1)
		atomic.AddInt64(&c.ipv6.numChecking, 1)
		atomic.AddInt64(&c.ipv6.numReadToCheck, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numReading, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numChecking, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numReadToCheck, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
		}
	}
}

func (c *connStats) readToTimeout(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numReading, -1)
		atomic.AddInt64(&c.ipv4.numTimeout, 1)
		atomic.AddInt64(&c.ipv4.numReadToTimeout, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numReading, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numTimeout, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numReadToTimeout, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numReading, -1)
		atomic.AddInt64(&c.ipv6.numTimeout, 1)
		atomic.AddInt64(&c.ipv6.numReadToTimeout, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numReading, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numTimeout, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numReadToTimeout, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) readToReset(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numReading, -1)
		atomic.AddInt64(&c.ipv4.numReset, 1)
		atomic.AddInt64(&c.ipv4.numReadToReset, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numReading, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numReset, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numReadToReset, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numReading, -1)
		atomic.AddInt64(&c.ipv6.numReset, 1)
		atomic.AddInt64(&c.ipv6.numReadToReset, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numReading, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numReset, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numReadToReset, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) readToError(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numReading, -1)
		atomic.AddInt64(&c.ipv4.numErr, 1)
		atomic.AddInt64(&c.ipv4.numReadToError, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numReading, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numErr, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numReadToError, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numReading, -1)
		atomic.AddInt64(&c.ipv6.numErr, 1)
		atomic.AddInt64(&c.ipv6.numReadToError, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numReading, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numErr, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numReadToError, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) checkToCreated(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numChecking, -1)
		atomic.AddInt64(&c.ipv4.numCreated, 1)
		atomic.AddInt64(&c.ipv4.numCheckToCreated, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCreated, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCheckToCreated, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numChecking, -1)
		atomic.AddInt64(&c.ipv6.numCreated, 1)
		atomic.AddInt64(&c.ipv6.numCheckToCreated, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCreated, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCheckToCreated, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
		}
	}
}

func (c *connStats) checkToRead(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numChecking, -1)
		atomic.AddInt64(&c.ipv4.numReading, 1)
		atomic.AddInt64(&c.ipv4.numCheckToRead, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numReading, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCheckToRead, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numChecking, -1)
		atomic.AddInt64(&c.ipv6.numReading, 1)
		atomic.AddInt64(&c.ipv6.numCheckToRead, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numReading, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCheckToRead, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
		}
	}
}

func (c *connStats) checkToFound(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numChecking, -1)
		atomic.AddInt64(&c.ipv4.numFound, 1)
		atomic.AddInt64(&c.ipv4.numCheckToFound, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numFound, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCheckToFound, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numChecking, -1)
		atomic.AddInt64(&c.ipv6.numFound, 1)
		atomic.AddInt64(&c.ipv6.numCheckToFound, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numFound, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCheckToFound, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) checkToError(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numChecking, -1)
		atomic.AddInt64(&c.ipv4.numErr, 1)
		atomic.AddInt64(&c.ipv4.numCheckToError, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numErr, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCheckToError, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numChecking, -1)
		atomic.AddInt64(&c.ipv6.numErr, 1)
		atomic.AddInt64(&c.ipv6.numCheckToError, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numErr, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCheckToError, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) checkToDiscard(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numChecking, -1)
		atomic.AddInt64(&c.ipv4.numIODiscarding, 1)
		atomic.AddInt64(&c.ipv4.numCheckToDiscard, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numIODiscarding, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numCheckToDiscard, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numChecking, -1)
		atomic.AddInt64(&c.ipv6.numIODiscarding, 1)
		atomic.AddInt64(&c.ipv6.numCheckToDiscard, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numChecking, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numIODiscarding, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numCheckToDiscard, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
		}
	}
}

func (c *connStats) discardToReset(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numIODiscarding, -1)
		atomic.AddInt64(&c.ipv4.numReset, 1)
		atomic.AddInt64(&c.ipv4.numDiscardToReset, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numIODiscarding, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numReset, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numDiscardToReset, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numIODiscarding, -1)
		atomic.AddInt64(&c.ipv6.numReset, 1)
		atomic.AddInt64(&c.ipv6.numDiscardToReset, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numIODiscarding, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numReset, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numDiscardToReset, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) discardToTimeout(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numIODiscarding, -1)
		atomic.AddInt64(&c.ipv4.numTimeout, 1)
		atomic.AddInt64(&c.ipv4.numDiscardToTimeout, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numIODiscarding, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numTimeout, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numDiscardToTimeout, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numIODiscarding, -1)
		atomic.AddInt64(&c.ipv6.numTimeout, 1)
		atomic.AddInt64(&c.ipv6.numDiscardToTimeout, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numIODiscarding, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numTimeout, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numDiscardToTimeout, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) discardToError(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numIODiscarding, -1)
		atomic.AddInt64(&c.ipv4.numErr, 1)
		atomic.AddInt64(&c.ipv4.numDiscardToError, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numIODiscarding, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numErr, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numDiscardToError, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numIODiscarding, -1)
		atomic.AddInt64(&c.ipv6.numErr, 1)
		atomic.AddInt64(&c.ipv6.numDiscardToError, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numIODiscarding, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numErr, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numDiscardToError, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func (c *connStats) discardToClose(asn uint, cc string, isIPv4 bool) {
	if isIPv4 {
		// Overall tracking
		atomic.AddInt64(&c.ipv4.numIODiscarding, -1)
		atomic.AddInt64(&c.ipv4.numClosed, 1)
		atomic.AddInt64(&c.ipv4.numDiscardToClose, 1)
		atomic.AddInt64(&c.ipv4.totalTransitions, 1)
		atomic.AddInt64(&c.ipv4.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v4geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v4geoIPMap[asn] = &asnCounts{}
				c.v4geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v4geoIPMap[asn].numIODiscarding, -1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numClosed, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numDiscardToClose, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v4geoIPMap[asn].numResolved, 1)
		}
	} else {
		// Overall tracking
		atomic.AddInt64(&c.ipv6.numIODiscarding, -1)
		atomic.AddInt64(&c.ipv6.numClosed, 1)
		atomic.AddInt64(&c.ipv6.numDiscardToClose, 1)
		atomic.AddInt64(&c.ipv6.totalTransitions, 1)
		atomic.AddInt64(&c.ipv6.numResolved, 1)

		// GeoIP tracking
		if isValidCC(cc) {
			c.m.Lock()
			defer c.m.Unlock()
			if _, ok := c.v6geoIPMap[asn]; !ok {
				// We haven't seen asn before, so add it to the map
				c.v6geoIPMap[asn] = &asnCounts{}
				c.v6geoIPMap[asn].cc = cc
			}
			atomic.AddInt64(&c.v6geoIPMap[asn].numIODiscarding, -1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numClosed, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numDiscardToClose, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].totalTransitions, 1)
			atomic.AddInt64(&c.v6geoIPMap[asn].numResolved, 1)
		}
	}
}

func isValidCC(cc string) bool {
	return cc != ""
}
