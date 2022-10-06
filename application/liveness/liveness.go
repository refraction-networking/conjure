package liveness

import (
	"fmt"
	"net"
	"sync"
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
	PrintStats(logger *log.Logger)
	Reset()
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
	m sync.RWMutex
	// newLivenessPass count of liveness tests that passed (non-live phantom) since reset()
	newLivenessPass int64

	// newLivenessFail count of liveness tests that failed (live phantom) since reset()
	newLivenessFail int64

	// newLivenessCached count of liveness tests that failed because they were in cache since reset(). Also counted in newLivenessFail
	newLivenessCached int64

	// start time of epoch to calculate per-second rates
	epochStart time.Time
}

func (s *stats) PrintStats(logger *log.Logger) {
	s.m.RLock()
	defer s.m.RUnlock()
	epochDur := time.Since(s.epochStart).Milliseconds()
	log.Infof("liveness-stats: %d (%f/s) valid %d (%f/s) live %d (%f/s) cached",
		s.newLivenessPass,
		float64(s.newLivenessPass)/float64(epochDur)*1000,
		s.newLivenessFail,
		float64(s.newLivenessFail)/float64(epochDur)*1000,
		s.newLivenessCached,
		float64(s.newLivenessCached)/float64(epochDur)*1000,
	)
}

func (s *stats) Reset() {
	s.m.Lock()
	defer s.m.Unlock()
	s.newLivenessPass = 0
	s.newLivenessFail = 0
	s.newLivenessCached = 0

	s.epochStart = time.Now()
}

func (s *stats) incPass() {
	s.m.Lock()
	defer s.m.Unlock()
	s.newLivenessPass++
}

func (s *stats) incFail() {
	s.m.Lock()
	defer s.m.Unlock()
	s.newLivenessFail++
}

func (s *stats) incCached() {
	s.m.Lock()
	defer s.m.Unlock()
	s.newLivenessCached++
}
