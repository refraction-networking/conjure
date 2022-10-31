package liveness

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/conjure/application/log"
)

// ErrCachedPhantom provides a constant expected error returned for cached
// liveness hits
var ErrCachedPhantom = errors.New("cached live host")

// ErrNotImplemented indicates that a feature will be implemented at some point
// but is not yet completed.
var ErrNotImplemented = errors.New("not supported yet")

// Tester provides a generic interface for testing hosts in phantom
// subnets for liveness. This prevents potential interference in connection
// creation.
type Tester interface {
	Stats
	PhantomIsLive(addr string, port uint16) (bool, error)
}

// Stats provides an interface to write out the collected metrics about liveness tester usage
type Stats interface {
	PrintAndReset(logger *log.Logger)
	PrintStats(logger *log.Logger)
	Reset()
}

type cache interface {
	Lookup(string) bool
	ClearExpired()
	Add(string, *cacheElement)

	// Len returns the number of elements in the cache
	Len() int

	// Cap returns a float percentage filled (0 if infinite capacity)
	Cap() float64
}

type cacheElement struct {
	cachedTime time.Time
}

// Config provides all params relating to liveness testing construction
type Config struct {
	// CacheDuration specifies the duration that a phantom IP identified as
	// "LIVE" using a liveness test is cached, preventing further lookups to the
	// address. Empty string disables caching for live phantom hosts.
	CacheDuration string `toml:"cache_expiration_time"`

	// CacheCapacity specifies the cache capacity to use for phantom IPs
	// identified as "LIVE". CacheDuration must be set otherwise no caching
	// occurs for live hosts.
	//
	// If unset or 0 no capacity is set and a map is used for the cache
	// otherwise cache will have finite capacity and implement LRU eviction.
	CacheCapacity int `toml:"cache_capacity"`

	// CacheDurationNonLive specifies the duration that a phantom IP identified
	// as "NOT LIVE" using a liveness test is cached, preventing further lookups
	// to the address. This should generally be shorter to be responsive to
	// remain responsive to hosts that become live. Empty string disables
	// caching for non-live phantom hosts.
	CacheDurationNonLive string `toml:"cache_expiration_nonlive"`

	// CacheCapacityNonLive specifies the cache capacity to use for phantom IPs
	// identified as "NOT LIVE". CacheDurationNonLive must be set otherwise no
	// caching occurs for non-live hosts.
	//
	// If unset or 0 no capacity is set and a map is used for the cache
	// otherwise cache will have finite capacity and implement LRU eviction.
	CacheCapacityNonLive int `toml:"cache_capacity_nonlive"`
}

var defaultConfig = &Config{
	CacheDuration:        "",
	CacheCapacity:        0,
	CacheDurationNonLive: "",
	CacheCapacityNonLive: 0,
}

// LivenessConfig identity function for reflection in composed Config type
func (c *Config) LivenessConfig() *Config {
	if c == nil {
		return defaultConfig
	}

	return c
}

// New provides a builder for the proper tester based on config.
func New(c *Config) (Tester, error) {
	if c == nil {
		c = defaultConfig
	}

	if c.CacheDuration == "" && c.CacheDurationNonLive == "" {
		return &UncachedLivenessTester{
			stats: &stats{},
		}, nil
	}

	clt := &CachedLivenessTester{
		stats: &stats{},
	}

	return clt, clt.Init(c)
}

func phantomIsLive(address string) (bool, error) {

	width := 4
	dialError := make(chan error, width)
	timeout := 750 * time.Millisecond

	testConnect := func() {
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			dialError <- err
			return
		}
		conn.Close()
		dialError <- nil
	}

	for i := 0; i < width; i++ {
		go testConnect()
	}

	time.Sleep(timeout)

	// If any return errors or connect then return nil before deadline it is live
	select {
	case err := <-dialError:
		if e, ok := err.(net.Error); ok && e.Timeout() {
			return false, fmt.Errorf("reached connection timeout")
		}
		if err != nil {
			return true, err
		}
		return true, fmt.Errorf("phantom picked up the connection")
	default:
		return false, fmt.Errorf("reached statistical timeout %v", timeout)
	}
}

type stats struct {
	// newLivenessPass count of liveness tests that passed (non-live phantom) since reset()
	newLivenessPass int64

	// newLivenessFail count of liveness tests that failed (live phantom) since reset()
	newLivenessFail int64

	// newLivenessCachedLive count of liveness tests that were resolved by consulting the
	// cache resulting in a "LIVE" designation since reset()
	newLivenessCachedLive int64

	// newLivenessCachedNonLive count of liveness tests that were resolved by consulting the
	// cache resulting in a "NOT LIVE" designation since reset()
	newLivenessCachedNonLive int64

	// start time of epoch to calculate per-second rates
	epochStart time.Time
}

func (s *stats) PrintAndReset(logger *log.Logger) {
	s.printStats(logger)
	s.Reset()
}

func (s *stats) PrintStats(logger *log.Logger) {
	s.printStats(logger)
}

func (s *stats) printStats(logger *log.Logger) {
	// prevent div by 0 if thread starvation happens
	var epochDur float64 = math.Max(float64(time.Since(s.epochStart).Milliseconds()), 1)

	nlp := atomic.LoadInt64(&s.newLivenessPass)
	nlf := atomic.LoadInt64(&s.newLivenessFail)
	nlcl := atomic.LoadInt64(&s.newLivenessCachedLive)
	nlcn := atomic.LoadInt64(&s.newLivenessCachedNonLive)
	total := math.Max(float64(nlp+nlf + +nlcl + nlcn), 1)

	logger.Infof("liveness-stats: %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s",
		nlp,
		float64(nlp)/float64(total)*100,
		float64(nlp)/float64(epochDur)*1000,
		nlf,
		float64(nlf)/float64(total)*100,
		float64(nlf)/float64(epochDur)*1000,
		nlcl,
		float64(nlcl)/float64(total)*100,
		float64(nlcl)/float64(epochDur)*1000,
		nlcn,
		float64(nlcn)/float64(total)*100,
		float64(nlcn)/float64(epochDur)*1000,
	)
}

func (s *stats) Reset() {
	atomic.StoreInt64(&s.newLivenessPass, 0)
	atomic.StoreInt64(&s.newLivenessFail, 0)
	atomic.StoreInt64(&s.newLivenessCachedLive, 0)
	atomic.StoreInt64(&s.newLivenessCachedNonLive, 0)

	s.epochStart = time.Now()
}

func (s *stats) incPass() {
	atomic.AddInt64(&s.newLivenessPass, 1)
}

func (s *stats) incFail() {
	atomic.AddInt64(&s.newLivenessFail, 1)
}

func (s *stats) incCached(live bool) {
	if live {
		atomic.AddInt64(&s.newLivenessCachedLive, 1)
	} else {
		atomic.AddInt64(&s.newLivenessCachedNonLive, 1)
	}
}
