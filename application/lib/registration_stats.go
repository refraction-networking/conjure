package lib

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/conjure/application/log"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// RegistrationStats track metrics relating to registration management and lifecycle
type RegistrationStats struct {
	epochStart time.Time

	activeRegistrations int64 // Current number of active registrations we have (marked valid - no error in validation i.e. bad phantom, bad covert, live phantom)

	newLocalRegistrations   int64 // Current registrations that were picked up from this detector (also included in newRegistrations)
	newAPIRegistrations     int64 // Current registrations that we heard about from the API (also included in newRegistrations)
	newSharedRegistrations  int64 // Current registrations that we heard about from the API sharing system (also included in newRegistrations)
	newUnknownRegistrations int64 // Current registrations that we heard about with unknown source (also included in newRegistrations)a
	newRegistrations        int64 // Added valid registrations since last reset() - non valid registrations should be counted entirely in newErrRegistrations
	newErrRegistrations     int64 // number of registrations that had some kinda error
	newDupRegistrations     int64 // number of duplicate registrations (doesn't uniquify, so might have some double counting)

	genMutex    sync.RWMutex                // Lock for generations map
	generations map[uint32]*generationStats // Map from ClientConf generation to number of registrations we saw using it

	newIngestMessages    int64 // How many Ingest messages were received this epoch
	newDroppedMessages   int64 // If the ingest channel ends up blocking how many registrations were dropped this epoch
	totalIngestMessages  int64 // How many messages have we seen total dropped or processed
	totalDroppedMessages int64 // How many registrations have been dropped total due to full channel
}

type generationStats struct {
	newRegistrations int64
}

func newRegistrationStats() *RegistrationStats {
	return &RegistrationStats{
		epochStart:  time.Now(),
		generations: make(map[uint32]*generationStats),
	}
}

// Reset implements the stats interface
func (s *RegistrationStats) Reset() {
	atomic.StoreInt64(&s.newRegistrations, 0)
	atomic.StoreInt64(&s.newLocalRegistrations, 0)
	atomic.StoreInt64(&s.newAPIRegistrations, 0)
	atomic.StoreInt64(&s.newSharedRegistrations, 0)
	atomic.StoreInt64(&s.newUnknownRegistrations, 0)
	atomic.StoreInt64(&s.newErrRegistrations, 0)
	atomic.StoreInt64(&s.newDupRegistrations, 0)

	atomic.StoreInt64(&s.newIngestMessages, 0)
	atomic.StoreInt64(&s.newDroppedMessages, 0)

	s.epochStart = time.Now()

	s.genMutex.Lock()
	defer s.genMutex.Unlock()
	s.generations = map[uint32]*generationStats{}
}

// PrintAndReset implements the stats interface
func (s *RegistrationStats) PrintAndReset(logger *log.Logger) {
	var epochDur float64 = math.Max(float64(time.Since(s.epochStart).Milliseconds()), 1)

	nr := atomic.LoadInt64(&s.newRegistrations)

	nlr := atomic.LoadInt64(&s.newLocalRegistrations)
	nar := atomic.LoadInt64(&s.newAPIRegistrations)
	nsr := atomic.LoadInt64(&s.newSharedRegistrations)
	nur := atomic.LoadInt64(&s.newUnknownRegistrations)

	ner := atomic.LoadInt64(&s.newErrRegistrations)
	ndr := atomic.LoadInt64(&s.newDupRegistrations)

	logger.Infof("reg-stats: 0 %d %d %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f/s %d %.3f/s",
		atomic.LoadInt64(&s.activeRegistrations),
		nr, float64(nr)/epochDur*100,

		nlr,
		float64(nlr)/float64(nr)*100,
		float64(nlr)/epochDur*100,

		nar,
		float64(nar)/float64(nr)*100,
		float64(nar)/epochDur*100,

		nsr,
		float64(nsr)/float64(nr)*100,
		float64(nsr)/epochDur*100,

		nur, // newUnknownRegistrations
		float64(nsr)/float64(nr)*100,
		float64(nur)/epochDur*100,

		ner, float64(ner)/epochDur*100,
		ndr, float64(ndr)/epochDur*100,
	)
	// this is done in func for lock / defer unlock without waiting for reset.
	func() {
		s.genMutex.RLock()
		defer s.genMutex.RUnlock()
		for gen, stats := range s.generations {
			logger.Infof("gen-stats: %d %d %.3f%% %.3f",
				gen,
				stats.newRegistrations,
				float64(stats.newRegistrations)/math.Max(float64(s.newRegistrations), 1),
				float64(stats.newRegistrations)/epochDur*1000,
			)
		}
	}()

	s.Reset()
}

// PrintAndReset implements the stats interface. Overrides the Registration stats
// implementation of PrintAndReset so we have access to the current state of the
// registration manager.
func (s *RegistrationManager) PrintAndReset(logger *log.Logger) {

	var epochDur float64 = math.Max(float64(time.Since(s.epochStart).Milliseconds()), 1)

	nr := atomic.LoadInt64(&s.newRegistrations)

	nlr := atomic.LoadInt64(&s.newLocalRegistrations)
	nar := atomic.LoadInt64(&s.newAPIRegistrations)
	nsr := atomic.LoadInt64(&s.newSharedRegistrations)
	nur := atomic.LoadInt64(&s.newUnknownRegistrations)

	ner := atomic.LoadInt64(&s.newErrRegistrations)
	ndr := atomic.LoadInt64(&s.newDupRegistrations)

	logger.Infof("reg-stats: %d %d %d %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f/s %d %.3f/s",
		s.registeredDecoys.TotalRegistrations(),
		atomic.LoadInt64(&s.activeRegistrations),
		nr, float64(nr)/epochDur*100,

		nlr,
		float64(nlr)/float64(nr)*100,
		float64(nlr)/epochDur*100,

		nar,
		float64(nar)/float64(nr)*100,
		float64(nar)/epochDur*100,

		nsr,
		float64(nsr)/float64(nr)*100,
		float64(nsr)/epochDur*100,

		nur, // newUnknownRegistrations
		float64(nsr)/float64(nr)*100,
		float64(nur)/epochDur*100,

		ner, float64(ner)/epochDur*100,
		ndr, float64(ndr)/epochDur*100,
	)

	l := len(s.ingestChan)
	c := cap(s.ingestChan)
	logger.Infof("reg-buf-stats: %d %.3f/s %d %.3f%% %.3f/s %d %d %d/%d %.3f%%",
		atomic.LoadInt64(&s.newIngestMessages),
		float64(atomic.LoadInt64(&s.newIngestMessages))/epochDur*1000, // x1000 convert /ms to /s
		atomic.LoadInt64(&s.newDroppedMessages),
		float64(atomic.LoadInt64(&s.newDroppedMessages))/math.Max(float64(atomic.LoadInt64(&s.newIngestMessages)), 1)*100,
		1000*float64(atomic.LoadInt64(&s.newDroppedMessages))/epochDur, // x1000 convert /ms to /s
		atomic.LoadInt64(&s.totalIngestMessages),
		atomic.LoadInt64(&s.totalDroppedMessages),
		l,
		c,
		float64(l)/float64(c)*100)

	// this is done in func for lock / defer unlock without waiting for reset.
	func() {
		s.genMutex.RLock()
		defer s.genMutex.RUnlock()
		for gen, stats := range s.generations {
			logger.Infof("gen-stats: %d %d %.3f%% %.3f",
				gen,
				stats.newRegistrations,
				float64(stats.newRegistrations)/math.Max(float64(nr), 1),
				float64(stats.newRegistrations)/epochDur*1000,
			)
		}
	}()

	s.Reset()
}

func (s *RegistrationStats) addIngestMessage() {
	atomic.AddInt64(&s.newIngestMessages, 1)
	atomic.AddInt64(&s.totalIngestMessages, 1)
}

func (s *RegistrationStats) addDroppedMessage() {
	atomic.AddInt64(&s.newDroppedMessages, 1)
	atomic.AddInt64(&s.totalDroppedMessages, 1)
}

// AddDupReg adds one to the count of registrations that saw duplicated this epoch
func (s *RegistrationStats) AddDupReg() {
	atomic.AddInt64(&s.newDupRegistrations, 1)
}

// AddErrReg adds one to the count of registrations that errored this epoch
func (s *RegistrationStats) AddErrReg() {
	atomic.AddInt64(&s.newErrRegistrations, 1)
}

// AddReg updates registration stats. Will only be called for registrations
// marked valid
func (s *RegistrationStats) AddReg(gen uint32, source *pb.RegistrationSource) {
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
	if stats, ok := s.generations[gen]; !ok || stats == nil {
		s.generations[gen] = &generationStats{}
	}
	atomic.AddInt64(&s.generations[gen].newRegistrations, 1)
	s.genMutex.Unlock()
}

// AddExpiredRegs updates registration stats count.
func (s *RegistrationStats) AddExpiredRegs(total, valid int64) {
	atomic.AddInt64(&s.activeRegistrations, -1*valid)
}
