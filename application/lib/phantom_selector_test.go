package lib

import (
	"encoding/hex"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhantomsIPSelectionAlt(t *testing.T) {

	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err, "issue decoding seedStr")

	//netStr := "192.122.190.0/24"
	netStr := "2001:48a8:687f:1::/64"
	_, net1, err := net.ParseCIDR(netStr)
	require.Nil(t, err, "unable to parse CIDR")

	// Select address with predetermined gen and seed
	addr, err := SelectAddrFromSubnet(seed, net1)
	require.Nil(t, err)
	require.Equal(t, addr.String(), "2001:48a8:687f:1:5fa4:c34c:434e:ddd")
}

func TestPhantomsGetSubnetsByGeneration(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	gen1 := phantomSelector.GetSubnetsByGeneration(1)
	require.NotNil(t, gen1.WeightedSubnets)
	require.Equal(t, len(gen1.WeightedSubnets), 1)
	assert.Contains(t, gen1.WeightedSubnets[0].Subnets, "192.122.190.0/24")

	genLatest := phantomSelector.GetSubnetsByGeneration(957)
	require.NotNil(t, genLatest.WeightedSubnets)
	assert.Equal(t, len(genLatest.WeightedSubnets), 2)
}

// We have removed the concept of Default SubnetConfig because it doesn't
// make much sense when there are independent deployments.
// The client almost certainly wont be able to connect to a phantom that the
// station selects from a default config since we won't pick the same phantom
// if they are using some generation config that we don't know about.
//
// This tests what happens with unknown generation (should return error)
func TestPhantomsSelectFromUnknownGen(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")

	phantomAddr, err := phantomSelector.Select(seed, 0, false)
	require.Equal(t, err.Error(), "generation number not recognized")
	assert.Nil(t, phantomAddr)
}

func TestPhantomsSeededSelectionV4(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	expectedAddr := "192.122.190.130"

	phantomAddr, err := phantomSelector.Select(seed, newGen, false)
	assert.Equal(t, expectedAddr, phantomAddr.String())

}

func TestPhantomsSeededSelectionV6(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	expectedAddr := "2001:48a8:687f:1:5fa4:c34c:434e:ddd"

	phantomAddr, err := phantomSelector.Select(seed, newGen, true)
	assert.Equal(t, expectedAddr, phantomAddr.String())
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
