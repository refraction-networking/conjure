package liveness

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"
)

const (
	CACHED_PHANTOM_MSG = "cached live host"
)

// LivenessTester provides a generic interface for testing hosts in phantom
// subnets for liveness. This prevents potential interference in connection
// creation.
type LivenessTester interface {
	PhantomIsLive(addr string, port uint16) (bool, error)
}

type cacheElement struct {
	isLive     bool
	cachedTime time.Time
}

// CachedLivenessTester implements LivenessTester interface with caching,
// PhantomIsLive will check historical results first before using the network to
// determine phantom liveness.
type CachedLivenessTester struct {
	ipCache             map[string]cacheElement
	signal              chan bool
	cacheExpirationTime time.Duration
}

// UncachedLivenessTester implements LivenessTester interface without caching,
// PhantomIsLive will always use the network to determine phantom liveness.
type UncachedLivenessTester struct {
}

// Init parses cache expiry duration and initializes the Cache.
func (blt *CachedLivenessTester) Init(expirationTime string) error {
	blt.ipCache = make(map[string]cacheElement)
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
	for ipAddr, status := range blt.ipCache {
		if time.Since(status.cachedTime) > blt.cacheExpirationTime {
			delete(blt.ipCache, ipAddr)
		}
	}
}

// PeriodicScan uses zmap to populate the cache of a CachedLivenessTester.
// Should be run as a goroutine as it may block for long periods of time while
// scanning.
func (blt *CachedLivenessTester) PeriodicScan(t string) {
	os.Create("block_list.txt")
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
			f, err = os.OpenFile("block_list.txt", os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Println("Unable to read blocklist file", err)
				f.Close()
			}

			for _, ip := range records {
				if ip[0] != "saddr" {
					if _, ok := blt.ipCache[ip[0]]; !ok {
						var val cacheElement
						val.isLive = true
						val.cachedTime = time.Now()
						blt.ipCache[ip[0]] = val
						_, err := f.WriteString(ip[0] + "/32" + "\n")
						if err != nil {
							fmt.Println("Unable to write blocklist file", err)
							f.Close()
						}
					}
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

// PhantomIsLive first checks the cached set of addressses for a fresh entry.
// If one is available and the host was measured to be live this is returned
// immediately and no network probes are sent. If the host was measured not
// live, the entry is stale, or there is not entry then network probes are sent
// and the result is then added to the cache.
func (blt *CachedLivenessTester) PhantomIsLive(addr string, port uint16) (bool, error) {
	// existing phantomIsLive() implementation
	if status, ok := blt.ipCache[addr]; ok {
		if time.Since(status.cachedTime) < blt.cacheExpirationTime {
			if status.isLive {
				return true, fmt.Errorf(CACHED_PHANTOM_MSG)
			}
		}
	}
	isLive, err := phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))
	var val cacheElement
	val.isLive = isLive
	val.cachedTime = time.Now()
	blt.ipCache[addr] = val
	return isLive, err
}

// PhantomIsLive sends 4 TCP syn packets to determine if the host will respond
// to traffic and potentially interfere with a connection if used as a phantom
// address. Measurement results are uncached, meaning endpoints are re-scanned
// every time.
func (blt *UncachedLivenessTester) PhantomIsLive(addr string, port uint16) (bool, error) {
	return phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))
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
