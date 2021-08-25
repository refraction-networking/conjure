package liveness

import (
	"fmt"
	"testing"
	"time"
	"os"
)

func TestBasic(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "../lib/test/phantom_subnets.toml")
	fmt.Println("Test Basic")
	var blt CachedLivenessTester
	blt.Init()
	go blt.Periodic_scan("Minute")
	time.Sleep(time.Minute * 8)
	blt.Stop()
}

func TestStop(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "../lib/test/phantom_subnets.toml")
	fmt.Println("Test Stop")
	var blt CachedLivenessTester
	blt.Init()
	go blt.Periodic_scan("Minutes")
	blt.Stop()
}
