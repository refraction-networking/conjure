package liveness

import (
	"fmt"
	"testing"
)

func TestBasic(t *testing.T) {
	fmt.Println("Test")
	var blt CachedLivenessTester
	blt.Init()
	blt.Periodic_scan("80","10M","10000")
}