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

type LivenessTester interface {
	PhantomIsLive(addr string, port uint16) (bool, error)
}

type CacheElement struct {
	isLive     bool
	cachedTime time.Time
}

type CachedLivenessTester struct {
	ipCache             map[string]CacheElement
	signal              chan bool
	cacheExpirationTime time.Duration
}

type UncachedLivenessTester struct {
}

func (blt *CachedLivenessTester) Init(expirationTime string) error {
	blt.ipCache = make(map[string]CacheElement)
	blt.signal = make(chan bool)

	convertedTime, err := time.ParseDuration(expirationTime)
	if err != nil {
		return fmt.Errorf("unable to parse cacheExpirationTime: %s", err)
	}
	blt.cacheExpirationTime = convertedTime

	return nil
}

func (blt *CachedLivenessTester) Stop() {
	blt.signal <- true
}

func (blt *CachedLivenessTester) ClearExpiredCache() {
	for ipAddr, status := range blt.ipCache {
		if time.Since(status.cachedTime) > blt.cacheExpirationTime {
			delete(blt.ipCache, ipAddr)
		}
	}
}

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
						var val CacheElement
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

func (blt *CachedLivenessTester) PhantomIsLive(addr string, port uint16) (bool, error) {
	// existing phantomIsLive() implementation
	if status, ok := blt.ipCache[addr]; ok {
		if time.Since(status.cachedTime) < blt.cacheExpirationTime {
			if status.isLive {
				return true, fmt.Errorf("cached live host")
			}
		}
	}
	isLive, err := phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))
	var val CacheElement
	val.isLive = isLive
	val.cachedTime = time.Now()
	blt.ipCache[addr] = val
	return isLive, err
}

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
			return false, fmt.Errorf("Reached connection timeout")
		}
		if err != nil {
			return true, err
		}
		return true, fmt.Errorf("Phantom picked up the connection")
	default:
		return false, fmt.Errorf("Reached statistical timeout %v", timeout)
	}
}
