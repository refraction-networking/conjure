package liveness

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/refraction-networking/conjure/application/log"
)

const defaultSizeLRU = 100000

// LRULivenessTester implements LivenessTester interface with caching,
// PhantomIsLive will check historical results first before using the network to
// determine phantom liveness.
//
// DO NOT USE THIS WITHOUT MORE TESTING - there is currently a locking issue
// somewhere that has not been resolved yet that results in unacceptable long
// periods where the zmq registration ingest blocks on phantom liveness
type LRULivenessTester struct {
	ipCache             map[string]*cacheElement
	lru                 *lru.Cache
	lruSize             int
	signal              chan bool
	cacheExpirationTime time.Duration
	m                   sync.RWMutex
	*stats
}

// Init parses cache expiry duration and initializes the Cache.
func (blt *LRULivenessTester) Init(expirationTime string) error {
	blt.m.Lock()
	defer blt.m.Unlock()

	// If an address is evicted from the LRU Cache remove it from the liveness map
	onEvict := func(k, v interface{}) {
		ipAddr := k.(string)
		delete(blt.ipCache, ipAddr)
	}
	if blt.lruSize <= 0 {
		blt.lruSize = defaultSizeLRU
	}
	lruCache, err := lru.NewWithEvict(blt.lruSize, onEvict)
	if err != nil {
		return err
	}

	blt.ipCache = make(map[string]*cacheElement)
	blt.signal = make(chan bool)
	blt.lru = lruCache

	convertedTime, err := time.ParseDuration(expirationTime)
	if err != nil {
		return fmt.Errorf("unable to parse cacheExpirationTime: %s", err)
	}
	blt.cacheExpirationTime = convertedTime

	return nil
}

// Stop end periodic scanning using running in separate goroutine. If periodic
// scanning is not running this will do nothing.
func (blt *LRULivenessTester) Stop() {
	blt.signal <- true
}

// ClearExpiredCache cleans out stale entries in the cache.
func (blt *LRULivenessTester) ClearExpiredCache() {
	blt.m.Lock()
	defer blt.m.Unlock()

	for ipAddr, status := range blt.ipCache {
		if time.Since(status.cachedTime) > blt.cacheExpirationTime {
			delete(blt.ipCache, ipAddr)
			blt.lru.Remove(ipAddr)
		}
	}
}

// PhantomIsLive first checks the cached set of addresses for a fresh entry.
// If one is available and the host was measured to be live this is returned
// immediately and no network probes are sent. If the host was measured not
// live, the entry is stale, or there is no entry then network probes are sent
// and the result is then added to the cache.
//
// Lock on mutex is taken for lookup, then for cache update. Do NOT hold mutex
// while scanning for liveness as this will make cache extremely slow.
func (blt *LRULivenessTester) PhantomIsLive(addr string, port uint16) (bool, error) {
	// cache lookup internal function to use RLock
	if live, err := blt.phantomLookup(addr, port); live || err != nil {
		blt.m.Lock()
		defer blt.m.Unlock()

		// add to stats
		blt.stats.incCached(live)

		// refresh this address in the LRU cache
		blt.lru.Add(addr, struct{}{})
		return live, err
	}

	// existing phantomIsLive() implementation
	isLive, err := phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))

	// Only write live things to cache since we always re-scan for non-live
	if isLive {
		blt.m.Lock()
		defer blt.m.Unlock()

		var val = &cacheElement{
			cachedTime: time.Now(),
		}
		blt.ipCache[addr] = val

		// add to stats
		blt.stats.incFail()

		// add the address to the LRU cache - potentially evicting an entry
		blt.lru.Add(addr, struct{}{})
	} else {
		// add to stats
		blt.stats.incPass()

	}

	return isLive, err
}

func (blt *LRULivenessTester) phantomLookup(addr string, port uint16) (bool, error) {
	blt.m.RLock()
	defer blt.m.RUnlock()

	if status, ok := blt.ipCache[addr]; ok {
		if time.Since(status.cachedTime) < blt.cacheExpirationTime {
			return true, ErrCachedPhantom
		}
	}
	return false, nil
}

// PrintStats implements the Stats interface extending from the stats struct
// to add logging for the cache capacity
func (blt *LRULivenessTester) PrintStats(logger *log.Logger) {

	blt.printStats(logger)
}

// PrintAndReset implements the Stats interface extending from the stats struct
// to add logging for the cache capacity
func (blt *LRULivenessTester) PrintAndReset(logger *log.Logger) {

	blt.printStats(logger)
	blt.stats.Reset()
}

func (blt *LRULivenessTester) printStats(logger *log.Logger) {
	s := blt.stats

	// prevent div by 0 if thread starvation happens
	var epochDur float64 = math.Max(float64(time.Since(s.epochStart).Milliseconds()), 1)

	nlp := atomic.LoadInt64(&s.newLivenessPass)
	nlf := atomic.LoadInt64(&s.newLivenessFail)
	nlcl := atomic.LoadInt64(&s.newLivenessCachedLive)
	nlcn := atomic.LoadInt64(&s.newLivenessCachedNonLive)
	total := math.Max(float64(nlp+nlf + +nlcl + nlcn), 1)

	logger.Infof("liveness-stats: %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d/%d (%f%%)",
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
		len(blt.ipCache),
		blt.lruSize,
		float64(len(blt.ipCache))/float64(math.Max(float64(blt.lruSize), 1)),
	)
}
