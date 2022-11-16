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

	newRegistrations   int64 // Added valid registrations since last reset() - non valid registrations should be counted entirely in newErrRegistrations
	newRegistrationsV4 int64 // number of registrations with not enabling IPv6
	newRegistrationsV6 int64 // number of registrations with enabling IPv6

	newLocalRegistrations   int64 // Current registrations that were picked up from this detector (also included in newRegistrations)
	newAPIRegistrations     int64 // Current registrations that we heard about from the API (also included in newRegistrations)
	newSharedRegistrations  int64 // Current registrations that we heard about from the API sharing system (also included in newRegistrations)
	newUnknownRegistrations int64 // Current registrations that we heard about with unknown source (also included in newRegistrations)a

	newBlocklistedPhantomReg int64 // number of registrations that blocklisted phantoms
	newErrRegistrations      int64 // number of registrations that had some kind of error
	newDupRegistrations      int64 // number of duplicate registrations (doesn't uniquify, so might have some double counting)

	newDNSResolutions int64 // number of registrations with domain name covert causing DNS resolutions.

	genMutex    sync.RWMutex                // Lock for generations map
	generations map[uint32]*generationStats // Map from ClientConf generation to number of registrations we saw using it

	lvMutex sync.RWMutex            // lock for library version stats
	lvStats map[uint32]*libverStats // map from library version to stats about registrations using that version

	ttMutex sync.RWMutex                             // lock for TransportType stats
	ttStats map[pb.TransportType]*transportTypeStats // map from library version to stats about registrations using that version

	newIngestMessages    int64 // How many Ingest messages were received this epoch
	newDroppedMessages   int64 // If the ingest channel ends up blocking how many registrations were dropped this epoch
	totalIngestMessages  int64 // How many messages have we seen total dropped or processed
	totalDroppedMessages int64 // How many registrations have been dropped total due to full channel
}

type generationStats struct {
	newRegistrations int64
}

type libverStats struct {
	newRegistrations int64
}

type transportTypeStats struct {
	newRegistrations int64
}

func newRegistrationStats() *RegistrationStats {
	return &RegistrationStats{
		epochStart:  time.Now(),
		generations: make(map[uint32]*generationStats),
		lvStats:     make(map[uint32]*libverStats),
		ttStats:     make(map[pb.TransportType]*transportTypeStats),
	}
}

// Reset implements the stats interface
func (s *RegistrationStats) Reset() {
	atomic.StoreInt64(&s.newRegistrations, 0)
	atomic.StoreInt64(&s.newRegistrationsV6, 0)
	atomic.StoreInt64(&s.newDNSResolutions, 0)

	atomic.StoreInt64(&s.newLocalRegistrations, 0)
	atomic.StoreInt64(&s.newAPIRegistrations, 0)
	atomic.StoreInt64(&s.newSharedRegistrations, 0)
	atomic.StoreInt64(&s.newUnknownRegistrations, 0)

	atomic.StoreInt64(&s.newErrRegistrations, 0)
	atomic.StoreInt64(&s.newDupRegistrations, 0)
	atomic.StoreInt64(&s.newRegistrationsV4, 0)
	atomic.StoreInt64(&s.newBlocklistedPhantomReg, 0)

	atomic.StoreInt64(&s.newIngestMessages, 0)
	atomic.StoreInt64(&s.newDroppedMessages, 0)

	s.epochStart = time.Now()

	func() {
		s.genMutex.Lock()
		defer s.genMutex.Unlock()
		s.generations = map[uint32]*generationStats{}
	}()

	func() {
		s.lvMutex.Lock()
		defer s.lvMutex.Unlock()
		s.lvStats = map[uint32]*libverStats{}
	}()

	func() {
		s.ttMutex.Lock()
		defer s.ttMutex.Unlock()
		s.ttStats = map[pb.TransportType]*transportTypeStats{}
	}()
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

	nv4 := atomic.LoadInt64(&s.newRegistrationsV4)
	nv6 := atomic.LoadInt64(&s.newRegistrationsV6)

	ndns := atomic.LoadInt64(&s.newDNSResolutions)

	logger.Infof("reg-stats: 0 %d %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s",
		atomic.LoadInt64(&s.activeRegistrations),
		nr, float64(nr)/epochDur*100,
		nv4, float64(nv4)/epochDur*1000,
		nv6, float64(nv6)/epochDur*1000,

		nlr, float64(nlr)/epochDur*1000,
		nar, float64(nar)/epochDur*1000,
		nsr, float64(nsr)/epochDur*1000,
		nur, float64(nur)/epochDur*1000,

		ner, float64(ner)/epochDur*1000,
		ndr, float64(ndr)/epochDur*1000,

		ndns, float64(ndns)/epochDur*1000,
	)

	// this is done in func for lock / defer unlock without waiting for reset.
	func() {
		s.genMutex.RLock()
		defer s.genMutex.RUnlock()
		for gen, stats := range s.generations {
			logger.Infof("gen-stats: %d %d %.3f",
				gen,
				stats.newRegistrations,
				float64(stats.newRegistrations)/epochDur*1000,
			)
		}
	}()

	// this is done in func for lock / defer unlock without waiting for reset.
	func() {
		s.ttMutex.RLock()
		defer s.ttMutex.RUnlock()
		for tt, stats := range s.ttStats {
			logger.Infof("tt-stats: %d %d %.3f",
				tt,
				stats.newRegistrations,
				float64(stats.newRegistrations)/epochDur*1000,
			)
		}
	}()

	// this is done in func for lock / defer unlock without waiting for reset.
	func() {
		s.lvMutex.RLock()
		defer s.lvMutex.RUnlock()
		for lv, stats := range s.lvStats {
			logger.Infof("libver-stats: %d %d %.3f",
				lv,
				stats.newRegistrations,
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

	nv4 := atomic.LoadInt64(&s.newRegistrationsV4)
	nv6 := atomic.LoadInt64(&s.newRegistrationsV6)

	ndns := atomic.LoadInt64(&s.newDNSResolutions)

	logger.Infof("reg-stats: %d %d %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s %d %.3f/s",
		s.registeredDecoys.TotalRegistrations(),
		atomic.LoadInt64(&s.activeRegistrations),
		nr, float64(nr)/epochDur*100,
		nv4, float64(nv4)/epochDur*1000,
		nv6, float64(nv6)/epochDur*1000,

		nlr, float64(nlr)/epochDur*1000,
		nar, float64(nar)/epochDur*1000,
		nsr, float64(nsr)/epochDur*1000,
		nur, float64(nur)/epochDur*1000,

		ner, float64(ner)/epochDur*1000,
		ndr, float64(ndr)/epochDur*1000,

		ndns, float64(ndns)/epochDur*1000,
	)

	l := len(s.ingestChan)
	c := cap(s.ingestChan)
	logger.Infof("reg-buf-stats: %d %.3f/s %d %.3f%% %.3f/s %d %d %d/%d %.3f%%",
		atomic.LoadInt64(&s.newIngestMessages),
		float64(atomic.LoadInt64(&s.newIngestMessages))/epochDur*1000, // x1000 convert /ms to /s
		atomic.LoadInt64(&s.newDroppedMessages),
		float64(atomic.LoadInt64(&s.newDroppedMessages))/math.Max(float64(atomic.LoadInt64(&s.newIngestMessages)), 1)*100,
		float64(atomic.LoadInt64(&s.newDroppedMessages))/epochDur*1000, // x1000 convert /ms to /s
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
			logger.Infof("gen-stats: %d %d %.3f",
				gen,
				stats.newRegistrations,
				float64(stats.newRegistrations)/epochDur*1000,
			)
		}
	}()

	// this is done in func for lock / defer unlock without waiting for reset.
	func() {
		s.ttMutex.RLock()
		defer s.ttMutex.RUnlock()
		for tt, stats := range s.ttStats {
			logger.Infof("tt-stats: %d %d %.3f",
				tt,
				stats.newRegistrations,
				float64(stats.newRegistrations)/epochDur*1000,
			)
		}
	}()

	// this is done in func for lock / defer unlock without waiting for reset.
	func() {
		s.lvMutex.RLock()
		defer s.lvMutex.RUnlock()
		for lv, stats := range s.lvStats {
			logger.Infof("libver-stats: %d %d %.3f",
				lv,
				stats.newRegistrations,
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

func (s *RegistrationStats) addDNSResolution() {
	atomic.AddInt64(&s.newDNSResolutions, 1)
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

// AddBlocklistedPhantomReg adds one to the count of registrations that errored this epoch
func (s *RegistrationStats) AddBlocklistedPhantomReg() {
	atomic.AddInt64(&s.newBlocklistedPhantomReg, 1)
}

// AddRegStats updates registration stats. Will only be called for registrations
// marked valid
func (s *RegistrationStats) AddRegStats(reg *DecoyRegistration) {
	gen := reg.DecoyListVersion
	source := reg.RegistrationSource
	tt := reg.Transport
	lv := reg.clientLibVer

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

	if reg.DarkDecoy.To4() == nil {
		atomic.AddInt64(&s.newRegistrationsV6, 1)
	} else {
		atomic.AddInt64(&s.newRegistrationsV4, 1)
	}

	func() {
		s.genMutex.Lock()
		defer s.genMutex.Unlock()
		if stats, ok := s.generations[gen]; !ok || stats == nil {
			s.generations[gen] = &generationStats{}
		}
		atomic.AddInt64(&s.generations[gen].newRegistrations, 1)
	}()

	func() {
		s.ttMutex.Lock()
		defer s.ttMutex.Unlock()
		if stats, ok := s.ttStats[tt]; !ok || stats == nil {
			s.ttStats[tt] = &transportTypeStats{}
		}
		atomic.AddInt64(&s.ttStats[tt].newRegistrations, 1)
	}()

	func() {
		s.lvMutex.Lock()
		defer s.lvMutex.Unlock()
		if stats, ok := s.lvStats[lv]; !ok || stats == nil {
			s.lvStats[lv] = &libverStats{}
		}
		atomic.AddInt64(&s.lvStats[lv].newRegistrations, 1)
	}()
}

// AddExpiredRegs updates registration stats count.
func (s *RegistrationStats) AddExpiredRegs(total, valid int64) {
	atomic.AddInt64(&s.activeRegistrations, -1*valid)
}
