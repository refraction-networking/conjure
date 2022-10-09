package liveness

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/conjure/application/log"
)

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

// Config provides all params relating to liveness testing construction
type Config struct {
	CacheDuration string
}

// New provides a builder for the proper tester based on config.
func New(c *Config) (Tester, error) {
	if c.CacheDuration == "" {
		return &UncachedLivenessTester{
			stats: &stats{},
		}, nil
	}

	clt := &CachedLivenessTester{
		stats: &stats{},
	}
	err := clt.Init(c.CacheDuration)
	return clt, err
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

	// newLivenessCached count of liveness tests that failed because they were in cache since reset(). Also counted in newLivenessFail
	newLivenessCached int64

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
	epochDur := time.Since(s.epochStart).Milliseconds()

	nlp := atomic.LoadInt64(&s.newLivenessPass)
	nlf := atomic.LoadInt64(&s.newLivenessFail)
	nlc := atomic.LoadInt64(&s.newLivenessCached)

	logger.Infof("liveness-stats: %d (%f/s) valid %d (%f/s) live %d (%f/s) cached",
		nlp,
		float64(nlp)/float64(epochDur)*1000,
		nlf,
		float64(nlf)/float64(epochDur)*1000,
		nlc,
		float64(nlc)/float64(epochDur)*1000,
	)
}

func (s *stats) Reset() {
	atomic.StoreInt64(&s.newLivenessPass, 0)
	atomic.StoreInt64(&s.newLivenessFail, 0)
	atomic.StoreInt64(&s.newLivenessCached, 0)

	s.epochStart = time.Now()
}

func (s *stats) incPass() {
	atomic.AddInt64(&s.newLivenessPass, 1)
}

func (s *stats) incFail() {
	atomic.AddInt64(&s.newLivenessFail, 1)
}

func (s *stats) incCached() {
	atomic.AddInt64(&s.newLivenessCached, 1)
}
