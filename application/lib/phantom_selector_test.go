package lib

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestPhantomsIPSelectionAlt(t *testing.T) {

	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err, "issue decoding seedStr")

	testCases := []struct {
		netStr   string
		expected string
	}{
		{
			netStr:   "2001:48a8:687f:1::/64",
			expected: "2001:48a8:687f:1:5fa4:c34c:434e:ddd",
		},
		{
			netStr:   "2001:48a8:687f:1::/128",
			expected: "2001:48a8:687f:1::",
		},
		{
			netStr:   "2001:48a8:687f:1::/127",
			expected: "2001:48a8:687f:1::1",
		},
		{
			netStr:   "10.0.0.0/8",
			expected: "10.219.31.130",
		},
		{
			netStr:   "10.0.0.0/32",
			expected: "10.0.0.0",
		},
		{
			netStr:   "10.0.0.0/30",
			expected: "10.0.0.2",
		},
	}

	for _, testCase := range testCases {
		_, net1, err := net.ParseCIDR(testCase.netStr)
		require.Nil(t, err, "unable to parse CIDR")

		// Select address with net and seed
		addr, err := SelectAddrFromSubnet(seed, net1)
		require.Nil(t, err)
		require.Equal(t, addr.String(), testCase.expected)
	}

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

	phantomAddr, err := phantomSelector.Select(seed, 0, phantomSelectionMinGeneration, false)
	require.Equal(t, err.Error(), "generation number not recognized")
	assert.Nil(t, phantomAddr)
}

func TestPhantomsSeededSelectionV4(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	expectedAddr := "192.122.190.130"

	phantomAddr, err := phantomSelector.Select(seed, newGen, phantomSelectionMinGeneration, false)
	require.Nil(t, err)
	assert.Equal(t, expectedAddr, phantomAddr.String())

}

// Client V1
func TestPhantomsSeededSelectionV6Varint(t *testing.T) {
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

	phantomAddr, err := phantomSelector.Select(seed, newGen, 1, true)
	require.Nil(t, err)
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

// TestPhantomsSeededSelectionV4Min ensures that minimal subnets work because
// they re useful to test limitations (i.e. multiple clients sharing a phantom
// address)
func TestPhantomsSeededSelectionV4Min(t *testing.T) {
	subnets, err := parseSubnets([]string{"192.122.190.0/32", "2001:48a8:687f:1::/128"})
	require.Nil(t, err)

	seed, err := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	phantomAddr, err := selectPhantomImplVarint(seed, subnets)
	require.Nil(t, err)

	possibleAddrs := []string{"192.122.190.0", "2001:48a8:687f:1::"}
	require.Contains(t, possibleAddrs, phantomAddr.String())
}

// TestPhantomSeededSelectionFuzz ensures that all phantom subnet sizes are
// viable including small (/31, /32, etc.) subnets which were previously
// experiencing a divide by 0.
func TestPhantomSeededSelectionFuzz(t *testing.T) {
	_, defaultV6, err := net.ParseCIDR("2001:48a8:687f:1::/64")
	require.Nil(t, err)

	var randSeed int64 = 1234
	r := rand.New(rand.NewSource(randSeed))

	// Add generation with only one v4 subnet that has a varying mask len
	for i := 0; i <= 32; i++ {
		s := "255.255.255.255/" + fmt.Sprint(i)
		_, variableSubnet, err := net.ParseCIDR(s)
		require.Nil(t, err)

		subnets := []*net.IPNet{defaultV6, variableSubnet}

		var seed = make([]byte, 32)
		for j := 0; j < 10000; j++ {
			n, err := r.Read(seed)
			require.Nil(t, err)
			require.Equal(t, n, 32)

			// phantomAddr, err := phantomSelector.Select(seed, newGen, false)
			phantomAddr, err := selectPhantomImplVarint(seed, subnets)
			require.Nil(t, err, "i=%d, j=%d, seed='%s'", i, j, hex.EncodeToString(seed))
			require.NotNil(t, phantomAddr)
		}
	}
}

// This tests Client V0
func TestPhantomsSeededSelectionLegacy(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	expectedAddr := "192.122.190.130"

	phantomAddr, err := phantomSelector.Select(seed, newGen, 0, false)
	require.Nil(t, err)
	assert.Equal(t, expectedAddr, phantomAddr.String())

}

// This tests Client V1
func TestPhantomsSeededSelectionVarint(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	expectedAddr := "192.122.190.130"

	phantomAddr, err := phantomSelector.Select(seed, newGen, 1, false)
	require.Nil(t, err)
	assert.Equal(t, expectedAddr, phantomAddr.String())
}

// This tests Client V2
func TestPhantomsSeededSelectionHkdf(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	expectedAddr := "192.122.190.164"

	phantomAddr, err := phantomSelector.Select(seed, newGen, 2, false)
	require.Nil(t, err)
	assert.Equal(t, expectedAddr, phantomAddr.String())
}

func TestPhantomsV6Hkdf(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	//expectedAddr := "2001:48a8:687f:1:5fa4:c34c:434e:ddd"
	expectedAddr := "2001:48a8:687f:1:d8f4:45cd:3ae:fcd4"

	phantomAddr, err := phantomSelector.Select(seed, newGen, 2, true)
	require.Nil(t, err)
	assert.Equal(t, expectedAddr, phantomAddr.String())
}

func ExpandSeed(seed, salt []byte, i int) []byte {
	bi := make([]byte, 8)
	binary.LittleEndian.PutUint64(bi, uint64(i))
	return hkdf.Extract(sha256.New, seed, append(salt, bi...))
}

// TestDuplicates demonstrates that selectPhantomImplVarint results in
// collisions due to random bias introduced by math/rand and Varint -- if one
// edits the ClientLibVersion to be 1 in phantomSelector.Select(...), it will
// detect the problem. Notice the leading bit of both seeds are 0, and the byte
// is the same (0x30) between the two tests that demonstrate generating the same
// IPv6 address.
//
// --- FAIL: TestDuplicates (0.00s)
//     phantom_selector_test.go:341: Generated duplicate IP; biased random. Both seeds 25 and 12 generated 2002::ee94:8e44:13ce:4e81
//         25: 30af851e2b8e4dd57db8830d5fc6f759bdc2c7a5a396f6641cc23604fa61c851
//         12: 301f4d8eba57f250e9fc3fa8205b3703fb4a6edbe4941f2a8ff2bc01e05051a9
// FAIL
func TestDuplicates(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 1, Subnets: []string{"2001:48a8:687f:1::/64"}},
			{Weight: 9, Subnets: []string{"2002::/64"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	salt := []byte("phantom-duplicate-test")

	// Set of IPs we have seen
	ipSet := map[string]int{}

	// The odds of this test generating a duplicate by chance is around 10^-10
	// (based on approximation of birthday bound n^2 / 2*m)
	for i := 0; i < 100000; i++ {

		// Get new random seed
		curSeed := ExpandSeed(seed, salt, i)

		// Get phantom address
		// addr, err := phantomSelector.Select(curSeed, newGen, 1, true)
		addr, err := phantomSelector.Select(curSeed, newGen, 2, true)
		if err != nil {
			t.Fatalf("Failed to select adddress: %v -- %s -- %v", err, hex.EncodeToString(curSeed), i)
		}
		//fmt.Printf("%s %v\n", hex.EncodeToString(curSeed), addr)

		if prevI, ok := ipSet[addr.String()]; ok {
			prevSeed := ExpandSeed(seed, salt, prevI)
			t.Fatalf("Generated duplicate IP; biased random. Both seeds %d and %d generated %v\n%d: %s\n%d: %s",
				i, prevI, addr, i, hex.EncodeToString(curSeed), prevI, hex.EncodeToString(prevSeed))
		}
		ipSet[addr.String()] = i
	}

}
