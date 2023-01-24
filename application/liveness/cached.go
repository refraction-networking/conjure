package liveness

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/conjure/application/log"
)

// CachedLivenessTester implements LivenessTester interface with caching,
// PhantomIsLive will check historical results first before using the network to
// determine phantom liveness.
type CachedLivenessTester struct {
	ipCacheLive    cache
	ipCacheNonLive cache
	signal         chan bool
	*stats
}

// Init parses cache expiry duration and initializes the Cache.
func (blt *CachedLivenessTester) Init(conf *Config) error {
	expirationLive := conf.CacheDuration
	expirationNonLive := conf.CacheDurationNonLive

	if expirationLive != "" {

		convertedTime, err := time.ParseDuration(expirationLive)
		if err != nil {
			return fmt.Errorf("unable to parse cacheExpirationLive: %s", err)
		}

		if conf.CacheCapacity != 0 {
			blt.ipCacheLive = newLRUCache(convertedTime, conf.CacheCapacity)

		} else {
			blt.ipCacheLive = newMapCache(convertedTime)
		}
	}

	if expirationNonLive != "" {
		convertedTime, err := time.ParseDuration(expirationNonLive)
		if err != nil {
			return fmt.Errorf("unable to parse cacheExpirationNonLive: %s", err)
		}

		if conf.CacheCapacity != 0 {
			blt.ipCacheNonLive = newLRUCache(convertedTime, conf.CacheCapacityNonLive)

		} else {
			blt.ipCacheNonLive = newMapCache(convertedTime)
		}
	}

	blt.signal = make(chan bool)

	return nil
}

// Stop end periodic scanning using running in separate goroutine. If periodic
// scanning is not running this will do nothing.
func (blt *CachedLivenessTester) Stop() {
	blt.signal <- true
}

// ClearExpiredCache cleans out stale entries in the cache.
func (blt *CachedLivenessTester) ClearExpiredCache() {
	if blt.ipCacheLive != nil {
		blt.ipCacheLive.ClearExpired()
	}

	if blt.ipCacheNonLive != nil {
		blt.ipCacheNonLive.ClearExpired()
	}
}

// PhantomIsLive first checks the cached set of addresses for a fresh entry. If
// one is available and this is returned immediately and no network probes are
// sent. If the host was not recently measured, the entry is stale, or there is
// no entry then network probes are sent and the result is then added to the
// cache.
//
// Lock on mutex is taken for lookup, then for cache update. Do NOT hold mutex
// while scanning for liveness as this will make cache extremely slow.
func (blt *CachedLivenessTester) PhantomIsLive(addr string, port uint16) (bool, error) {
	// cache lookup internal function to use RLock
	if live, err := blt.phantomLookup(addr, port); live || err != nil {
		// add to stats
		blt.stats.incCached(live)
		return live, err
	}

	// existing phantomIsLive() implementation
	isLive, err := phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))

	var val = &cacheElement{
		cachedTime: time.Now(),
	}

	if isLive {
		// add to stats
		blt.stats.incFail()

		// Add to cache if enabled
		if blt.ipCacheLive != nil {
			blt.ipCacheLive.Add(addr, val)
		}
	} else {
		// add to stats
		blt.stats.incPass()

		// Add to cache if enabled
		if blt.ipCacheNonLive != nil {
			blt.ipCacheNonLive.Add(addr, val)

		}
	}

	return isLive, err
}

func (blt *CachedLivenessTester) phantomLookup(addr string, port uint16) (bool, error) {
	if blt.ipCacheLive != nil {
		if ok := blt.ipCacheLive.Lookup(addr); ok {
			return true, ErrCachedPhantom
		}
	}

	if blt.ipCacheNonLive != nil {
		if ok := blt.ipCacheNonLive.Lookup(addr); ok {
			return false, ErrCachedPhantom
		}
	}
	return false, nil
}

// PrintStats implements the Stats interface extending from the stats struct
// to add logging for the cache capacity
func (blt *CachedLivenessTester) PrintStats(logger *log.Logger) {
	blt.printStats(logger)
}

// PrintAndReset implements the Stats interface extending from the stats struct
// to add logging for the cache capacity
func (blt *CachedLivenessTester) PrintAndReset(logger *log.Logger) {
	blt.printStats(logger)
	blt.stats.Reset()
}

func (blt *CachedLivenessTester) printStats(logger *log.Logger) {
	s := blt.stats

	// prevent div by 0 if thread starvation happens
	var epochDur float64 = math.Max(float64(time.Since(s.epochStart).Milliseconds()), 1)
	nlp := atomic.LoadInt64(&s.newLivenessPass)
	nlf := atomic.LoadInt64(&s.newLivenessFail)
	nlcl := atomic.LoadInt64(&s.newLivenessCachedLive)
	nlcn := atomic.LoadInt64(&s.newLivenessCachedNonLive)
	total := math.Max(float64(nlp+nlf+nlcl+nlcn), 1)

	liveCacheLen := 0
	var liveCacheCapPct float64 = 0
	if blt.ipCacheLive != nil {
		liveCacheLen = blt.ipCacheLive.Len()
		liveCacheCapPct = float64(liveCacheLen) / float64(blt.ipCacheLive.Cap()) * 100
	}

	nonLiveCacheLen := 0
	var nonLiveCacheCapPct float64 = 0
	if blt.ipCacheLive != nil {
		nonLiveCacheLen = blt.ipCacheNonLive.Len()
		nonLiveCacheCapPct = float64(nonLiveCacheLen) / float64(blt.ipCacheNonLive.Cap()) * 100
	}

	logger.Infof("liveness-stats: %d %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %.3f/s %d %.3f%% %d %.3f%%",
		nlp+nlf+nlcl+nlcn,
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
		liveCacheLen,
		liveCacheCapPct,
		nonLiveCacheLen,
		nonLiveCacheCapPct,
	)
}

/*
// // Disabled because we don't have a good reason to pre-populate the cache
// // currently and this dead code has a call to exec.

// PeriodicScan uses zmap to populate the cache of a CachedLivenessTester. //
Should be run as a goroutine as it may block for long periods of time while //
scanning. func (blt *CachedLivenessTester) PeriodicScan(t string) {
allowListAddr := os.Getenv("PHANTOM_SUBNET_LOCATION") for { select { case
<-blt.signal: return default: _, err := exec.Command("zmap", "-p", "443", "-O",
"csv", "-f", "saddr,classification", "-P", "4", "--output-filter=
(classification = rst || classification = synack)", "-b", "block_list.txt",
"-w", allowListAddr, "-o", "result.csv").Output() if err != nil {
fmt.Println(err)
            }

            f, err := os.Open("result.csv")
            if err != nil {
                fmt.Println("Unable to read input file", err)
                f.Close()
            }

            csvReader := csv.NewReader(f)
            records, err := csvReader.ReadAll()
            if err != nil {
                fmt.Println("Unable to parse file as CSV", err)
            }

            f.Close()
            f, err = os.OpenFile("block_list.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
            if err != nil {
                fmt.Println("Unable to read blocklist file", err)
                f.Close()
            }

            for _, ip := range records {
                if ip[0] != "saddr" {
                    func() {
                        // closure to ensure mutex unlocks in case of error.
                        blt.m.Lock()
                        defer blt.m.Unlock()

                        if _, ok := blt.ipCache[ip[0]]; !ok {
                            var val = &cacheElement{
                                isLive:     true,
                                cachedTime: time.Now(),
                            }
                            blt.ipCache[ip[0]] = val
                            _, err := f.WriteString(ip[0] + "/32" + "\n")
                            if err != nil {
                                fmt.Println("Unable to write blocklist file", err)
                                f.Close()
                            }
                        }
                    }()
                }
            }
            f.Close()

            err = os.Remove("result.csv")
            if err != nil {
                fmt.Println("Unable to delete result.csv", err)
            }

            fmt.Println("Scanned once")
            if t == "Minute" {
                time.Sleep(time.Minute * 2)
            } else if t == "Hour" {
                time.Sleep(time.Hour * 2)
            } else {
                fmt.Println("Invalid scanning interval")
                return
            }

        }
    }
}
*/
