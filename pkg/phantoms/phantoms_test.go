package phantoms

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"testing"

	pb "github.com/refraction-networking/conjure/proto"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestIPSelectionBasic(t *testing.T) {
	//seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	//require.Nil(t, err)
	offset := big.NewInt(0x7eadbeefcafed00d)

	netStr := "2001:48a8:687f:1::/64"
	_, net1, err := net.ParseCIDR(netStr)
	require.Nil(t, err)

	addr, err := SelectAddrFromSubnetOffset(net1, offset)
	require.Nil(t, err)
	//require.Equal(t, "2001:48a8:687f:1:5fa4:c34c:434e:ddd", addr.String())
	require.Equal(t, "2001:48a8:687f:1:7ead:beef:cafe:d00d", addr.String())
}

func TestOffsetTooLarge(t *testing.T) {

	offset := big.NewInt(256)
	netStr := "10.1.2.0/24"
	_, net1, err := net.ParseCIDR(netStr)
	require.Nil(t, err)

	// Offset too big
	addr, err := SelectAddrFromSubnetOffset(net1, offset)
	if err == nil {
		t.Fatalf("Error: expected error, got address %v", addr)
	}

	// Offset that is just fine
	offset = big.NewInt(255)
	addr, err = SelectAddrFromSubnetOffset(net1, offset)
	require.Nil(t, err)
	require.Equal(t, "10.1.2.255", addr.String())
}

func TestSelectWeightedMany(t *testing.T) {

	count := []int{0, 0}
	loops := 1000
	r := rand.New(rand.NewSource(12345))
	_, net1, err := net.ParseCIDR("192.122.190.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, net2, err := net.ParseCIDR("141.219.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	var ps = &pb.PhantomSubnetsList{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: &w1, Subnets: []string{"192.122.190.0/24"}},
			{Weight: &w9, Subnets: []string{"141.219.0.0/16"}},
		},
	}

	for i := 1; i <= loops; i++ {
		seed := make([]byte, 16)
		_, err := r.Read(seed)
		if err != nil {
			t.Fatalf("Failed to generate seed: %v", err)
		}

		addr, err := SelectPhantom(seed, ps, nil, true)
		if err != nil {
			t.Fatalf("Failed to select adddress: %v -- %s, %v, %v, %v -- %v", err, hex.EncodeToString(seed), ps, "None", true, count)
		}

		if net1.Contains(*addr) {
			count[0]++
		} else if net2.Contains(*addr) {
			count[1]++
		} else {
			t.Fatalf("failed to parse pb.PhantomSubnetsList: %v, %v, %v", seed, true, ps)
		}
	}
	t.Logf("%.2f%%, %.2f%%", float32(count[0])/float32(loops)*100.0, float32(count[1])/float32(loops)*100.0)
}

func TestWeightedSelection(t *testing.T) {

	count := []int{0, 0}
	loops := 1000
	r := rand.New(rand.NewSource(5421212341231))
	w := uint32(1)
	var ps = &pb.PhantomSubnetsList{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: &w, Subnets: []string{"1"}},
			{Weight: &w, Subnets: []string{"2"}},
		},
	}

	for i := 1; i <= loops; i++ {
		seed := make([]byte, 16)
		_, err := r.Read(seed)
		if err != nil {
			t.Fatalf("Failed to generate seed: %v", err)
		}

		sa := getSubnets(ps, seed, true)
		if sa == nil {
			t.Fatalf("failed to parse pb.PhantomSubnetsList: %v, %v, %v", seed, true, ps)

		} else if sa[0] == "1" {
			count[0]++
		} else if sa[0] == "2" {
			count[1]++
		}

	}
	t.Logf("%.2f%%, %.2f%%", float32(count[0])/float32(loops)*100.0, float32(count[1])/float32(loops)*100.0)
}

var w1 = uint32(1)
var w9 = uint32(9)
var phantomSubnets = &pb.PhantomSubnetsList{
	WeightedSubnets: []*pb.PhantomSubnets{
		{Weight: &w9, Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
		{Weight: &w1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
	},
}

func TestSelectFilter(t *testing.T) {
	seed, err := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	p, err := SelectPhantomWeighted([]byte(seed), phantomSubnets, V4Only)
	require.Nil(t, err)
	//require.Equal(t, "192.122.190.130", p.String())
	require.Equal(t, "192.122.190.164", p.String())

	p, err = SelectPhantomWeighted([]byte(seed), phantomSubnets, V6Only)
	require.Nil(t, err)
	//require.Equal(t, "2001:48a8:687f:1:5fa4:c34c:434e:ddd", p.String())
	require.Equal(t, "2001:48a8:687f:1:5da6:63e0:48a4:b3e", p.String())

	p, err = SelectPhantomWeighted([]byte(seed), phantomSubnets, nil)
	require.Nil(t, err)
	//require.Equal(t, "2001:48a8:687f:1:5fa4:c34c:434e:ddd", p.String())
	require.Equal(t, "2001:48a8:687f:1:d8f4:45cd:3ae:fcd4", p.String())
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

	phantomAddr, err := selectIPAddr(seed, subnets)
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
			phantomAddr, err := selectIPAddr(seed, subnets)
			require.Nil(t, err, "i=%d, j=%d, seed='%s'", i, j, hex.EncodeToString(seed))
			require.NotNil(t, phantomAddr)
		}
	}
}

func ExpandSeed(seed, salt []byte, i int) []byte {
	bi := make([]byte, 8)
	binary.LittleEndian.PutUint64(bi, uint64(i))
	return hkdf.Extract(sha256.New, seed, append(salt, bi...))
}

// This test serves two functions. First, it checks if there's any duplicates
// when there should not be (generating 100k 64-bit numbers, we don't expect any duplicates)
// Second, we check if the weighting is approximately correct (within +/-0.5%)
func TestForDuplicates(t *testing.T) {

	// Constraints:
	// -Only one subnet per weight
	// -Must be large enough subnets (e.g. /64) to avoid birthday bound problems (100k no collision)
	// -Subnets cannot overlap
	var w40 = uint32(40)
	var ps = &pb.PhantomSubnetsList{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: &w1, Subnets: []string{"2001:48a8:687f:1::/64"}},
			{Weight: &w9, Subnets: []string{"2002::/64"}},
			{Weight: &w40, Subnets: []string{"2003::/64"}},
		},
	}

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	salt := []byte("phantom-duplicate-test")

	// Set of IPs we have seen
	ipSet := map[string]int{}

	// Count of IPs in each set
	netMap := map[string]int{}
	weights := map[string]int{}

	totWeights := 0
	snets, err := parseSubnets(getSubnets(ps, nil, false))
	require.Nil(t, err)
	for _, phantomSubnet := range ps.WeightedSubnets {
		snet := phantomSubnet.Subnets[0]
		weights[snet] = int(*phantomSubnet.Weight)
		netMap[snet] = 0
		totWeights += int(*phantomSubnet.Weight)
	}

	totTrials := 100000
	// The odds of this test generating a duplicate by chance is around 10^-10
	// (based on approximation of birthday bound n^2 / 2*m)
	for i := 0; i < totTrials; i++ {

		// Get new random seed
		curSeed := ExpandSeed(seed, salt, i)

		// Get phantom address
		addr, err := SelectPhantom(curSeed, ps, nil, true)
		if err != nil {
			t.Fatalf("Failed to select adddress: %v -- %s, %v, %v, %v -- %v", err, hex.EncodeToString(curSeed), ps, "None", true, i)
		}
		//fmt.Printf("%s %v\n", hex.EncodeToString(curSeed), addr)

		if prev_i, ok := ipSet[addr.String()]; ok {
			prevSeed := ExpandSeed(seed, salt, prev_i)
			t.Fatalf("Generated duplicate IP; biased random. Both seeds %d and %d generated %v\n%d: %s\n%d: %s",
				i, prev_i, addr, i, hex.EncodeToString(curSeed), prev_i, hex.EncodeToString(prevSeed))
		}
		ipSet[addr.String()] = i

		for _, snet := range snets {
			if snet.Contains(*addr) {
				netMap[snet.String()] += 1
			}
		}
	}

	// Check if weights are approximately right
	margin := totTrials / 200 // +/- 0.5%
	for snet, count := range netMap {
		expectedCount := totTrials * weights[snet] / totWeights
		if count < (expectedCount-margin) || count > (expectedCount+margin) {
			t.Fatalf("Generated weight outside bound: %s had %d but expected %d, off by more than %d\n",
				snet, count, expectedCount, margin)
		}
		//fmt.Printf("%s: had %d, weight %d/%d (expected %d +/-%d)\n", snet, count, weights[snet], totWeights, expectedCount, margin)
	}
}
