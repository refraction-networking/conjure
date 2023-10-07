package phantoms

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"testing"

	"github.com/refraction-networking/conjure/pkg/core"
	pb "github.com/refraction-networking/conjure/proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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

	phantomAddr, err := phantomSelector.Select(seed, 0, core.PhantomSelectionMinGeneration, false)
	require.Equal(t, err.Error(), "generation number not recognized")
	assert.Nil(t, phantomAddr)
}

// This tests Client V2
func TestPhantomsSeededSelectionHkdf(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: proto.Uint32(9), Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
			{Weight: proto.Uint32(1), Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
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
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: proto.Uint32(9), Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
			{Weight: proto.Uint32(1), Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")

	phantomAddr, err := phantomSelector.Select(seed, newGen, 2, true)
	require.Nil(t, err)
	assert.True(t, phantomAddr.To4() == nil)
	assert.True(t, phantomAddr.To16() != nil)
}

func TestPhantomsCompareClientAndStation(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: proto.Uint32(9), Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}, RandomizeDstPort: proto.Bool(true)},
			{Weight: proto.Uint32(1), Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}, RandomizeDstPort: proto.Bool(true)},
		},
	}

	var psl = &pb.PhantomSubnetsList{
		WeightedSubnets: newConf.WeightedSubnets,
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed := make([]byte, 32)

	for i := 0; i < 10_000; i++ {
		_, err := rand.Read(seed)
		require.Nil(t, err)

		clientAddr, clientErr := SelectPhantom(seed, psl, V4Only, true)
		stationAddr, stationErr := phantomSelector.Select(seed, newGen, uint(core.CurrentClientLibraryVersion()), false)
		if stationErr != nil && clientErr != nil {
			require.Equal(t, clientErr.Error(), stationErr.Error())
		} else {
			require.Nil(t, stationErr)
			require.Nil(t, clientErr)
			require.NotNil(t, clientAddr)
			require.NotNil(t, stationAddr)
			if stationAddr != nil && clientAddr != nil {
				require.Equal(t, clientAddr.String(), stationAddr.String(), "client:%s, station:%s", clientAddr, stationAddr)
			}
		}

		clientAddr, clientErr = SelectPhantom(seed, psl, V6Only, true)
		stationAddr, stationErr = phantomSelector.Select(seed, newGen, uint(core.CurrentClientLibraryVersion()), true)
		if stationErr != nil && clientErr != nil {
			require.Equal(t, clientErr.Error(), stationErr.Error())
		} else {
			require.Nil(t, stationErr)
			require.Nil(t, clientErr)
			require.NotNil(t, clientAddr)
			require.NotNil(t, stationAddr)
			if stationAddr != nil && clientAddr != nil {
				require.Equal(t, clientAddr.String(), stationAddr.String(), "client:%s, station:%s", clientAddr, stationAddr)
			}
		}
	}
}

func TestPhantomsCompareClientAndStationCount(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: proto.Uint32(9), Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}, RandomizeDstPort: proto.Bool(true)},
			{Weight: proto.Uint32(1), Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}, RandomizeDstPort: proto.Bool(true)},
		},
	}

	var psl = &pb.PhantomSubnetsList{
		WeightedSubnets: newConf.WeightedSubnets,
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed := make([]byte, 32)
	iterations := 10_000
	v4 := 0
	v6 := 0
	v4ClientErrs := 0
	v4StationErrs := 0
	v6ClientErrs := 0
	v6StationErrs := 0
	for i := 0; i < iterations; i++ {
		_, err := rand.Read(seed)
		require.Nil(t, err)

		clientAddr, clientErr := SelectPhantom(seed, psl, V4Only, true)
		stationAddr, stationErr := phantomSelector.Select(seed, newGen, uint(core.CurrentClientLibraryVersion()), false)
		if stationErr != nil {
			v4StationErrs++
		}
		if clientErr != nil {
			v4ClientErrs++
		}
		if stationErr != nil && clientErr != nil && stationErr.Error() == clientErr.Error() {
			v4++
		}

		if stationAddr != nil && clientAddr != nil && stationAddr.String() == clientAddr.String() {
			v4++
		}

		clientAddr, clientErr = SelectPhantom(seed, psl, V6Only, true)
		stationAddr, stationErr = phantomSelector.Select(seed, newGen, uint(core.CurrentClientLibraryVersion()), true)
		if stationErr != nil {
			v6StationErrs++
		}
		if clientErr != nil {
			v6ClientErrs++
		}

		if stationErr != nil && clientErr != nil && stationErr.Error() == clientErr.Error() {
			v6++
		}

		if stationAddr != nil && clientAddr != nil && stationAddr.String() == clientAddr.String() {
			v6++
		}
	}
	t.Log("V4: ", v4, "V6: ", v6, "V4ClientErrs: ", v4ClientErrs, "V4StationErrs: ", v4StationErrs, "V6ClientErrs: ", v6ClientErrs, "V6StationErrs: ", v6StationErrs)
	require.Equal(t, iterations, v4)
	require.Equal(t, iterations, v6)
}

// TestDuplicates demonstrates that selectPhantomImplVarint results in
// collisions due to random bias introduced by math/rand and Varint -- if one
// edits the ClientLibVersion to be 1 in phantomSelector.Select(...), it will
// detect the problem. Notice the leading bit of both seeds are 0, and the byte
// is the same (0x30) between the two tests that demonstrate generating the same
// IPv6 address.
//
// --- FAIL: TestDuplicates (0.00s)
//
//	phantom_selector_test.go:341: Generated duplicate IP; biased random. Both seeds 25 and 12 generated 2002::ee94:8e44:13ce:4e81
//	    25: 30af851e2b8e4dd57db8830d5fc6f759bdc2c7a5a396f6641cc23604fa61c851
//	    12: 301f4d8eba57f250e9fc3fa8205b3703fb4a6edbe4941f2a8ff2bc01e05051a9
//
// FAIL
func TestDuplicates(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: proto.Uint32(1), Subnets: []string{"2001:48a8:687f:1::/64"}},
			{Weight: proto.Uint32(9), Subnets: []string{"2002::/64"}},
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
