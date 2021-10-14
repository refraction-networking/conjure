package liveness

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// To run the measuremest commands set the environment variable when running go test
//     $ MEASUREMENTS=1 go test -v
func TestBasic(t *testing.T) {
	if os.Getenv("MEASUREMENTS") != "1" {
		t.Skip("skiping long running measurement based tests")
	}
	os.Setenv("PHANTOM_SUBNET_LOCATION", "../lib/test/phantom_subnets.toml")
	fmt.Println("Test Basic")
	var blt CachedLivenessTester
	blt.Init("2.0h")
	go blt.PeriodicScan("Minute")
	time.Sleep(time.Minute * 8)
	blt.Stop()
}

// To run the measuremest commands set the environment variable when running go test
//     $ MEASUREMENTS=1 go test -v
func TestStop(t *testing.T) {
	if os.Getenv("MEASUREMENTS") != "1" {
		t.Skip("skiping long running measurement based tests")
	}
	os.Setenv("PHANTOM_SUBNET_LOCATION", "../lib/test/phantom_subnets.toml")
	fmt.Println("Test Stop")
	var blt CachedLivenessTester
	blt.Init("2.0h")
	go blt.PeriodicScan("Minutes")
	blt.Stop()
}

func TestUncachedLiveness(t *testing.T) {

	ult := UncachedLivenessTester{}

	liveness, response := ult.PhantomIsLive("1.1.1.1.", 80)

	if liveness != true {
		t.Fatalf("Host is live, detected as NOT live: %v\n", response)
	}

	liveness, response = ult.PhantomIsLive("192.0.0.2", 443)
	if liveness != false {
		t.Fatalf("Host is NOT live, detected as live: %v\n", response)
	}

	liveness, response = ult.PhantomIsLive("2606:4700:4700::64", 443)
	if liveness != true {
		t.Fatalf("Host is live, detected as NOT live: %v\n", response)
	}
}

func TestCachedLiveness(t *testing.T) {

	clt := CachedLivenessTester{}
	err := clt.Init("1h")
	if err != nil {
		t.Fatalf("failed to init cached liveness tester: %s", err)
	}

	liveness, response := clt.PhantomIsLive("1.1.1.1.", 80)
	if liveness != true {
		t.Fatalf("Host is live, detected as NOT live: %v\n", response)
	}
	if status, ok := clt.ipCache["1.1.1.1."]; !ok || status.isLive != true {
		t.Fatalf("Host is live, but not cached as live")
	}

	liveness, response = clt.PhantomIsLive("192.0.0.2", 443)
	if liveness != false {
		t.Fatalf("Host is NOT live, detected as live: %v\n", response)
	}
	if status, ok := clt.ipCache["192.0.0.2"]; !ok || status.isLive != false {
		t.Fatalf("Host is NOT live, but cached as live")
	}

	liveness, response = clt.PhantomIsLive("2606:4700:4700::64", 443)
	if liveness != true {
		t.Fatalf("Host is live, detected as NOT live: %v\n", response)
	}
	if status, ok := clt.ipCache["2606:4700:4700::64"]; !ok || status.isLive != true {
		t.Fatalf("Host is not live, but cached as live")
	}

	// lookup for known live cached values should be fast since it doesn't go to network.
	start := time.Now()
	_, _ = clt.PhantomIsLive("2606:4700:4700::64", 443)
	_, _ = clt.PhantomIsLive("1.1.1.1.", 80)
	if time.Since(start) > time.Duration(1*time.Millisecond) {
		t.Fatal("Lookup for cached live entries taking too long")
	}

}
