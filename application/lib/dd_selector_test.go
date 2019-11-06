package lib

import (
	"testing"
	"fmt"
)


func TestGetSubnetsByGeneration(t *testing.T) {
	dd, err := NewDDIpSelector()
	if err != nil {
		t.Fatalf("Failed to create the DDIpSelector Object: %v\n", err)
	}

	fmt.Println( "All Generations: ", dd.Networks)
	gen1 := dd.GetSubnetsByGeneration(1)
	fmt.Println(gen1)

	genDefault := dd.GetSubnetsByGeneration(100)
	fmt.Println(genDefault)

}

func TestSelectIpv4FromDefault(t *testing.T) {
	dd, err := NewDDIpSelector()
	if err != nil {
		t.Fatalf("Failed to create the DDIpSelector Object: %v\n", err)
	}

	seed := []byte{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
	}

	phantomAddr, err := dd.Select(seed, 0, false)

	expectedAddr := "192.122.190.120"
	if expectedAddr != phantomAddr.String() {
		t.Fatalf("Expected Addr %v -- Got %v", expectedAddr, phantomAddr)
	}
}


func TestSeededSelectionV4(t *testing.T) {
	dd, err := NewDDIpSelector()
	if err != nil {
		t.Fatalf("Failed to create the DDIpSelector Object: %v\n", err)
	}
	newGen := dd.AddGeneration(-1, []string{"18.0.0.0/8", "1234::/64"})


	seed := []byte{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
	}

	phantomAddr, err := dd.Select(seed, newGen, false)

	expectedAddr := "18.35.40.45"
	if expectedAddr != phantomAddr.String() {
		t.Fatalf("Expected Addr %v -- Got %v", expectedAddr, phantomAddr)
	}
}


func TestSeededSelectionV6(t *testing.T) {
	dd, err := NewDDIpSelector()
	if err != nil {
		t.Fatalf("Failed to create the DDIpSelector Object: %v\n", err)
	}
	newGen := dd.AddGeneration(-1, []string{"18.0.0.0/8", "1234::/64"})

	seed := []byte{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
	}

	phantomAddr, err := dd.Select(seed, newGen, true)

	expectedAddr := "1234::507:90c:e17:181a"
	if expectedAddr != phantomAddr.String() {
		t.Fatalf("Expected Addr %v -- Got %v", expectedAddr, phantomAddr)
	}
}