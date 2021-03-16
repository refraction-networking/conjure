package lib

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPSelectionAlt(t *testing.T) {

	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	if err != nil {
		t.Fatalf("Issue decoding seedStr")
	}

	//netStr := "192.122.190.0/24"
	netStr := "2001:48a8:687f:1::/64"
	_, net1, err := net.ParseCIDR(netStr)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := SelectAddrFromSubnet(seed, net1)
	if err != nil {
		t.Fatal(err)
	} else if addr.String() != "2001:48a8:687f:1:5fa4:c34c:434e:ddd" {
		t.Fatalf("Wrong Address Selected: %v -> expected (%v)", addr, "2001:48a8:687f:1:5fa4:c34c:434e:ddd")
	}

}

func TestGetSubnetsByGeneration(t *testing.T) {
	dd, err := NewPhantomIPSelector()
	if err != nil {
		t.Fatalf("Failed to create the PhantomIPSelector Object: %v\n", err)
	}

	t.Log("All Generations: ", dd.Networks)
	gen1 := dd.GetSubnetsByGeneration(1)
	t.Log(gen1)

	genDefault := dd.GetSubnetsByGeneration(100)
	t.Log(genDefault)

}

func TestSelectIpv4FromDefault(t *testing.T) {
	dd, err := NewPhantomIPSelector()
	if err != nil {
		t.Fatalf("Failed to create the PhantomIPSelector Object: %v\n", err)
	}
	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")

	phantomAddr, err := dd.Select(seed, 0, false)

	expectedAddr := "192.122.190.130"
	if expectedAddr != phantomAddr.String() {
		t.Fatalf("Expected Addr %v -- Got %v", expectedAddr, phantomAddr)
	}
}

func TestSeededSelectionV4(t *testing.T) {
	dd, err := NewPhantomIPSelector()
	if err != nil {
		t.Fatalf("Failed to create the PhantomIPSelector Object: %v\n", err)
	}

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := dd.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")

	phantomAddr, err := dd.Select(seed, newGen, false)

	expectedAddr := "192.122.190.130"
	if expectedAddr != phantomAddr.String() {
		t.Fatalf("Expected Addr %v -- Got %v", expectedAddr, phantomAddr)
	}
}

func TestSeededSelectionV6(t *testing.T) {
	dd, err := NewPhantomIPSelector()
	if err != nil {
		t.Fatalf("Failed to create the PhantomIPSelector Object: %v\n", err)
	}
	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := dd.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")

	phantomAddr, err := dd.Select(seed, newGen, true)

	expectedAddr := "2001:48a8:687f:1:5fa4:c34c:434e:ddd"
	if expectedAddr != phantomAddr.String() {
		t.Fatalf("Expected Addr %v -- Got %v", expectedAddr, phantomAddr)
	}
}

func TestPhantomsV6OnlyFilter(t *testing.T) {
	testNets := []string{"192.122.190.0/24", "2001:48a8:687f:1::/64", "2001:48a8:687f:1::/64"}
	testNetsParsed, err := parseSubnets(testNets)
	require.Nil(t, err)
	require.Equal(t, 3, len(testNetsParsed))

	testNetsParsed, err = V6Only(testNetsParsed)
	require.Nil(t, err)
	require.Equal(t, 2, len(testNetsParsed))

}
