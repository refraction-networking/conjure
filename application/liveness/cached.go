package liveness

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/refraction-networking/conjure/application/log"
)

const (

	// CachedPhantomMessage provides a constant expected error returned for cached liveness hits
	CachedPhantomMessage = "cached live host"
)

type cacheElement struct {
	isLive     bool
	cachedTime time.Time
}

// CachedLivenessTester implements LivenessTester interface with caching,
// PhantomIsLive will check historical results first before using the network to
// determine phantom liveness.
type CachedLivenessTester struct {
	ipCache             map[string]*cacheElement
	signal              chan bool
	cacheExpirationTime time.Duration
	m                   sync.RWMutex
	*stats
}

// Init parses cache expiry duration and initializes the Cache.
func (blt *CachedLivenessTester) Init(expirationTime string) error {
	blt.m.Lock()
	defer blt.m.Unlock()

	blt.ipCache = make(map[string]*cacheElement)
	blt.signal = make(chan bool)

	convertedTime, err := time.ParseDuration(expirationTime)
	if err != nil {
		return fmt.Errorf("unable to parse cacheExpirationTime: %s", err)
	}
	blt.cacheExpirationTime = convertedTime

	return nil
}

// Stop end periodic scanning using running in separate goroutine. If periodic
// scanning is not running this will do nothing.
func (blt *CachedLivenessTester) Stop() {
	blt.signal <- true
}

// ClearExpiredCache cleans out stale entries in the cache.
func (blt *CachedLivenessTester) ClearExpiredCache() {
	blt.m.Lock()
	defer blt.m.Unlock()

	for ipAddr, status := range blt.ipCache {
		if time.Since(status.cachedTime) > blt.cacheExpirationTime {
			delete(blt.ipCache, ipAddr)
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
func (blt *CachedLivenessTester) PhantomIsLive(addr string, port uint16) (bool, error) {
	// cache lookup internal function to use RLock
	if live, err := blt.phantomLookup(addr, port); live || err != nil {
		// add to stats
		blt.stats.incCached()
		return live, err
	}

	// existing phantomIsLive() implementation
	isLive, err := phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))

	// Only write live things to cache since we always re-scan for non-live
	if isLive {
		// add to stats
		blt.stats.incFail()

		// add to cache
		blt.m.Lock()
		defer blt.m.Unlock()

		var val = &cacheElement{
			isLive:     isLive,
			cachedTime: time.Now(),
		}
		blt.ipCache[addr] = val

	} else {
		// add to stats
		blt.stats.incPass()

	}

	return isLive, err
}

func (blt *CachedLivenessTester) phantomLookup(addr string, port uint16) (bool, error) {
	blt.m.RLock()
	defer blt.m.RUnlock()

	if status, ok := blt.ipCache[addr]; ok {
		if time.Since(status.cachedTime) < blt.cacheExpirationTime {
			if status.isLive {
				return true, fmt.Errorf(CachedPhantomMessage)
			}
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
	epochDur := time.Since(s.epochStart).Milliseconds()
	logger.Infof("liveness-stats: %d (%f/s) valid %d (%f/s) live %d (%f/s) cached, capacity:%d",
		s.newLivenessPass,
		float64(s.newLivenessPass)/float64(epochDur)*1000,
		s.newLivenessFail,
		float64(s.newLivenessFail)/float64(epochDur)*1000,
		s.newLivenessCached,
		float64(s.newLivenessCached)/float64(epochDur)*1000,
		len(blt.ipCache),
	)
}

// PeriodicScan uses zmap to populate the cache of a CachedLivenessTester.
// Should be run as a goroutine as it may block for long periods of time while
// scanning.
func (blt *CachedLivenessTester) PeriodicScan(t string) {
	allowListAddr := os.Getenv("PHANTOM_SUBNET_LOCATION")
	for {
		select {
		case <-blt.signal:
			return
		default:
			_, err := exec.Command("zmap", "-p", "443", "-O", "csv", "-f", "saddr,classification", "-P", "4", "--output-filter= (classification = rst || classification = synack)", "-b", "block_list.txt", "-w", allowListAddr, "-o", "result.csv").Output()
			if err != nil {
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
