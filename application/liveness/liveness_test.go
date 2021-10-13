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
