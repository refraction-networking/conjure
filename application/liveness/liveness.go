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

type CachedLivenessTester struct{
	ip_cache map[string]bool
}

type UncachedLivenessTester struct{
}


func (blt *CachedLivenessTester) Init(){
	blt.ip_cache = make(map[string]bool)
}

//limit should be left empty if scanning the whole internet, for local test only
//Call with goroutine
func (blt *CachedLivenessTester) Periodic_scan(port string, bandwidth string, limit string){
	limit = "-n " + limit
	for{
		_, err := exec.Command("sudo","zmap","-B",bandwidth,"-p",port,limit,"-o","result.csv").Output()
		if err != nil {
			fmt.Println(err)
		}
		//fmt.Println(output)
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
		
		//fmt.Println(records)
		f.Close()

		for _, ip := range records{
			blt.ip_cache[ip[0]] = true
		}
		//fmt.Println(blt.ip_cache)
		fmt.Println("Scanned once")
		time.Sleep(time.Hour)
	}
}

// PhantomIsLive - Test whether the phantom is live using
// 8 syns which returns syn-acks from 99% of sites within 1 second.
// see  ZMap: Fast Internet-wide Scanning  and Its Security Applications
// https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_durumeric.pdf
//
// return:	bool	true  - host is live
// 					false - host is not liev
//			error	reason decision was made
func (blt *CachedLivenessTester) PhantomIsLive(addr string, port uint16) (bool, error){
    // existing phantomIsLive() implementation
	if val, ok := blt.ip_cache[addr]; ok {
		//should port be considered here?
		return true, fmt.Errorf("cached live host")
	}
	isLive, err := phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))
	if isLive {
		blt.ip_cache[addr] = true
	}
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