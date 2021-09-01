package liveness

import (
	"fmt"
	"net"
	"strconv"
	"time"
	"encoding/csv"
	"os"
	"os/exec"
)

type LivenessTester interface {
    PhantomIsLive(addr string, port uint16) (bool, error)
}

type Cache_element struct {
    is_live 	bool
	cached_time	time.Time
}

type CachedLivenessTester struct{
	ip_cache 				map[string]Cache_element
	signal 					chan bool
	cache_expiration_time 	float64
}

type UncachedLivenessTester struct{
}


func (blt *CachedLivenessTester) Init(expiration_time float64){
	blt.ip_cache = make(map[string]Cache_element)
	blt.signal = make(chan bool)
	blt.cache_expiration_time = expiration_time
}

func (blt *CachedLivenessTester) Stop(){
	blt.signal <- true
}

func (blt *CachedLivenessTester) Clear_expired_cache(){
	for ip_addr, status := range blt.ip_cache {
        if time.Now().Sub(status.cached_time).Hours() > blt.cache_expiration_time {
			delete(blt.ip_cache, ip_addr)
		}
    }
}

func (blt *CachedLivenessTester) Periodic_scan(t string){
	os.Create("block_list.txt")
	allow_list_addr := os.Getenv("PHANTOM_SUBNET_LOCATION")
	for{
		select {
		case <- blt.signal:
			return
		default:
			_, err := exec.Command("zmap","-p","443","-O","csv","-f","saddr,classification","-P","4","--output-filter= (classification = rst || classification = synack)","-b","block_list.txt","-w",allow_list_addr,"-o","result.csv").Output()
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

			for _, ip := range records{
				if ip[0] != "saddr"{
					if _, ok := blt.ip_cache[ip[0]]; !ok {
						var val Cache_element
						val.is_live = true
						val.cached_time = time.Now()
						blt.ip_cache[ip[0]] = val
						_, err := f.WriteString(ip[0]+"/32"+"\n")
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

func (blt *CachedLivenessTester) PhantomIsLive(addr string, port uint16) (bool, error){
    // existing phantomIsLive() implementation
	if status, ok := blt.ip_cache[addr]; ok {
		if time.Now().Sub(status.cached_time).Hours() < blt.cache_expiration_time {
			if status.is_live {
				return true, fmt.Errorf("cached live host")		
			}
		}
	}
	isLive, err := phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))
	var val Cache_element
	val.is_live = isLive
	val.cached_time = time.Now()
	blt.ip_cache[addr] = val
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
