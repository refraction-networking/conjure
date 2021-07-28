package liveness

import (
	"fmt"
	"testing"
	"time"
)

func TestBasic(t *testing.T) {
	fmt.Println("Test Basic")
	var blt CachedLivenessTester
	blt.Init()
	go blt.Periodic_scan("Minute")
	time.Sleep(time.Minute * 8)
	blt.Stop()
}

func TestStop(t *testing.T) {
	fmt.Println("Test Stop")
	var blt CachedLivenessTester
	blt.Init()
	go blt.Periodic_scan("Minutes")
	blt.Stop()
}
