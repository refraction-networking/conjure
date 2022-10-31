package lib

import (
	golog "log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/conjure/application/log"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

type stats interface {
	// PrintAndReset is intended to allow each stats module to summarize metrics
	// from the current epoch out through the logger and then reset any stats
	// that need reset as the start of a new epoch.
	PrintAndReset(logger *log.Logger)

	Reset()
}

// Stats contains counts of many things we want to keep track of in any given epoch
// as well as reference to modular metrics interfaces from related modules. These
// are used to print usage in a regulated and consumable way.
//
// fields are int64 because we occasionally need to atomically subtract, which is
// not supported for uint64
type Stats struct {
	logger *log.Logger

	moduleStats []stats

	// TODO JMWAMPLE REMOVE
	activeConns            int64 // incremented on add, decremented on remove, not reset
	newConns               int64 // new connections since last stats.reset()
	newErrConns            int64 // new connections that had some sort of error since last reset()
	newMissedRegistrations int64 // number of "missed" registrations (as seen by a connection with no registration)

	// TODO JMWAMPLE REMOVE
	activeRegistrations     int64            // Current number of active registrations we have (marked valid - no error in validation i.e. bad phantom, bad covert, live phantom)
	newLocalRegistrations   int64            // Current registrations that were picked up from this detector (also included in newRegistrations)
	newAPIRegistrations     int64            // Current registrations that we heard about from the API (also included in newRegistrations)
	newSharedRegistrations  int64            // Current registrations that we heard about from the API sharing system (also included in newRegistrations)
	newUnknownRegistrations int64            // Current registrations that we heard about with unknown source (also included in newRegistrations)a
	newRegistrations        int64            // Added valid registrations since last reset() - non valid registrations should be counted entirely in newErrRegistrations
	newErrRegistrations     int64            // number of registrations that had some kinda error
	newDupRegistrations     int64            // number of duplicate registrations (doesn't uniquify, so might have some double counting)
	genMutex                *sync.Mutex      // Lock for generations map
	generations             map[uint32]int64 // Map from ClientConf generation to number of registrations we saw using it

	// TODO JMWAMPLE REMOVE
	newBytesUp   int64 // TODO: need to redo halfPipe to make this not really jumpy
	newBytesDown int64 // ditto

	// TODO JMWAMPLE REMOVE
	newLivenessPass   int64 // Liveness tests that passed (non-live phantom) since reset()
	newLivenessFail   int64 // Liveness tests that failed (live phantom) since reset()
	newLivenessCached int64 // Liveness tests that failed because they were in cache since reset(). Also counted in newLivenessFail
}

var statInstance Stats
var statsOnce sync.Once

// Stat returns our singleton for stats
func Stat() *Stats {
	statsOnce.Do(initStats)
	return &statInstance
}

func (s *Stats) AddStatsModule(sm stats) {
	if sm == nil {
		return
	}

	s.moduleStats = append(s.moduleStats, sm)
}

func initStats() {
	logger := log.New(os.Stdout, "[STATS] ", golog.Ldate|golog.Lmicroseconds)
	statInstance = Stats{
		logger:      logger,
		generations: make(map[uint32]int64),
		genMutex:    &sync.Mutex{},
	}

	// Periodic PrintStats()
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			statInstance.PrintStats()
		}
	}()
}

func (s *Stats) Reset() {
	atomic.StoreInt64(&s.newConns, 0)
	atomic.StoreInt64(&s.newErrConns, 0)
	atomic.StoreInt64(&s.newRegistrations, 0)
	atomic.StoreInt64(&s.newLocalRegistrations, 0)
	atomic.StoreInt64(&s.newAPIRegistrations, 0)
	atomic.StoreInt64(&s.newSharedRegistrations, 0)
	atomic.StoreInt64(&s.newUnknownRegistrations, 0)
	atomic.StoreInt64(&s.newMissedRegistrations, 0)
	atomic.StoreInt64(&s.newErrRegistrations, 0)
	atomic.StoreInt64(&s.newDupRegistrations, 0)
	atomic.StoreInt64(&s.newLivenessPass, 0)
	atomic.StoreInt64(&s.newLivenessFail, 0)
	atomic.StoreInt64(&s.newLivenessCached, 0)
	atomic.StoreInt64(&s.newBytesUp, 0)
	atomic.StoreInt64(&s.newBytesDown, 0)
}

func (s *Stats) ResetAll() {
	for _, module := range s.moduleStats {
		if module != nil {
			module.Reset()
		}
	}
	s.Reset()
}

func (s *Stats) PrintStats() {
	for _, module := range s.moduleStats {
		if module != nil {
			module.PrintAndReset(s.logger)
		}
	}

	s.logger.Infof("Conns: %d cur %d new %d err Regs: %d cur %d new (%d local %d API %d shared %d unknown) %d miss %d err %d dup LiveT: %d valid %d live %d cached Byte: %d up %d down",
		atomic.LoadInt64(&s.activeConns), atomic.LoadInt64(&s.newConns), atomic.LoadInt64(&s.newErrConns),
		atomic.LoadInt64(&s.activeRegistrations),
		atomic.LoadInt64(&s.newRegistrations),
		atomic.LoadInt64(&s.newLocalRegistrations), atomic.LoadInt64(&s.newAPIRegistrations), atomic.LoadInt64(&s.newSharedRegistrations), atomic.LoadInt64(&s.newUnknownRegistrations),
		atomic.LoadInt64(&s.newMissedRegistrations),
		atomic.LoadInt64(&s.newErrRegistrations), atomic.LoadInt64(&s.newDupRegistrations),
		atomic.LoadInt64(&s.newLivenessPass), atomic.LoadInt64(&s.newLivenessFail), atomic.LoadInt64(&s.newLivenessCached),
		atomic.LoadInt64(&s.newBytesUp), atomic.LoadInt64(&s.newBytesDown))
	s.Reset()
}

func (s *Stats) AddConn() {
	atomic.AddInt64(&s.activeConns, 1)
	atomic.AddInt64(&s.newConns, 1)
}

func (s *Stats) CloseConn() {
	atomic.AddInt64(&s.activeConns, -1)
}

func (s *Stats) ConnErr() {
	atomic.AddInt64(&s.activeConns, -1)
	atomic.AddInt64(&s.newErrConns, 1)
}

// will only be called for registrations marked valid
func (s *Stats) AddReg(generation uint32, source *pb.RegistrationSource) {
	atomic.AddInt64(&s.activeRegistrations, 1)
	atomic.AddInt64(&s.newRegistrations, 1)

	if *source == pb.RegistrationSource_Detector {
		atomic.AddInt64(&s.newLocalRegistrations, 1)
	} else if *source == pb.RegistrationSource_API {
		atomic.AddInt64(&s.newAPIRegistrations, 1)
	} else if *source == pb.RegistrationSource_DetectorPrescan {
		atomic.AddInt64(&s.newSharedRegistrations, 1)
	} else {
		atomic.AddInt64(&s.newUnknownRegistrations, 1)
	}
	s.genMutex.Lock()
	s.generations[generation] += 1
	s.genMutex.Unlock()
}

func (s *Stats) AddDupReg() {
	atomic.AddInt64(&s.newDupRegistrations, 1)
}

func (s *Stats) AddErrReg() {
	atomic.AddInt64(&s.newErrRegistrations, 1)
}

// should only be called for registrations marked valid
func (s *Stats) ExpireReg(generation uint32, source *pb.RegistrationSource) {
	atomic.AddInt64(&s.activeRegistrations, -1)

	s.genMutex.Lock()
	s.generations[generation] -= 1
	s.genMutex.Unlock()
}

func (s *Stats) AddMissedReg() {
	atomic.AddInt64(&s.newMissedRegistrations, 1)
}

func (s *Stats) AddLivenessPass() {
	atomic.AddInt64(&s.newLivenessPass, 1)
}

func (s *Stats) AddLivenessFail() {
	atomic.AddInt64(&s.newLivenessFail, 1)
}

func (s *Stats) AddLivenessCached() {
	atomic.AddInt64(&s.newLivenessCached, 1)
}

func (s *Stats) AddBytesUp(n int64) {
	atomic.AddInt64(&s.newBytesUp, n)
}

func (s *Stats) AddBytesDown(n int64) {
	atomic.AddInt64(&s.newBytesDown, n)
}

func (s *Stats) AddBytes(n int64, dir string) {
	if dir == "Up" {
		s.AddBytesUp(n)
	} else {
		s.AddBytesDown(n)
	}
}
