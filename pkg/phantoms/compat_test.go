package phantoms

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	v0 "github.com/refraction-networking/conjure/internal/compatability/v0"
	v1 "github.com/refraction-networking/conjure/internal/compatability/v1"
	"github.com/refraction-networking/conjure/pkg/core"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// This tests Client V1
func TestPhantomsSeededSelectionVarint(t *testing.T) {
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
	expectedAddr := "192.122.190.130"

	phantomAddr, err := phantomSelector.Select(seed, newGen, 1, false)
	require.Nil(t, err)
	assert.Equal(t, expectedAddr, phantomAddr.String())
}

// Client V1
func TestPhantomsSeededSelectionV6Varint(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: proto.Uint32(9), Subnets: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}, RandomizeDstPort: proto.Bool(true)},
			{Weight: proto.Uint32(1), Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}, RandomizeDstPort: proto.Bool(true)},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")

	phantomAddr, err := phantomSelector.Select(seed, newGen, 1, true)
	require.Nil(t, err)
	assert.True(t, phantomAddr.To4() == nil)
	assert.True(t, phantomAddr.To16() != nil)
}

func TestPhantomsCompatV1(t *testing.T) {
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
		clientAddr, clientErr := v1.SelectPhantom(seed, psl, v1.V4Only, true)
		stationAddr, stationErr := phantomSelector.Select(seed, newGen, core.PhantomSelectionMinGeneration, false)
		if stationErr != nil {
			require.Equal(t, stationErr, clientErr)
		} else {
			require.Nil(t, clientErr)
			require.Nil(t, stationErr)
			require.Equal(t, clientAddr.String(), stationAddr.String(), "client:%s, station:%s", clientAddr, stationAddr)
		}

		// Check IPv6 Match
		require.Nil(t, err)
		clientAddr, clientErr = v1.SelectPhantom(seed, psl, v1.V6Only, true)
		stationAddr, stationErr = phantomSelector.Select(seed, newGen, core.PhantomSelectionMinGeneration, true)
		if stationErr != nil {
			require.Equal(t, stationErr, clientErr)
		} else {
			require.Nil(t, clientErr)
			require.Nil(t, stationErr)
			require.Equal(t, clientAddr.String(), stationAddr.String(), "client:%s, station:%s", clientAddr, stationAddr)
		}
	}
}

func TestPhantomsSeededSelectionV4(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	phantomSelector, err := NewPhantomIPSelector()
	require.Nil(t, err, "Failed to create the PhantomIPSelector Object")

	var newConf = &SubnetConfig{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: proto.Uint32(9), Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}, RandomizeDstPort: proto.Bool(true)},
			{Weight: proto.Uint32(1), Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}, RandomizeDstPort: proto.Bool(true)},
		},
	}

	newGen := phantomSelector.AddGeneration(-1, newConf)

	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	expectedAddr := "192.122.190.130"

	phantomAddr, err := phantomSelector.Select(seed, newGen, 0, false)
	require.Nil(t, err)
	assert.Equal(t, expectedAddr, phantomAddr.String())

}

// This tests Client V0
func TestPhantomsSeededSelectionLegacy(t *testing.T) {
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
	expectedAddr := "192.122.190.130"

	phantomAddr, err := phantomSelector.Select(seed, newGen, 0, false)
	require.Nil(t, err)
	assert.Equal(t, expectedAddr, phantomAddr.String())

}

func TestPhantomsCompatV0(t *testing.T) {
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
		clientAddr, clientErr := v0.SelectPhantom(seed, psl, v0.V4Only, true)
		stationAddr, stationErr := phantomSelector.Select(seed, newGen, 0, false)
		func() {
			if errors.Is(clientErr, v0.ErrSubnetParseBug) {
				return // it is possible the errors don't match properly whe the client hits this bug
			} else if stationErr != nil && clientErr != nil {
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
		}()

		// Check IPv6 Match
		require.Nil(t, err)
		clientAddr, clientErr = v0.SelectPhantom(seed, psl, v0.V6Only, true)
		stationAddr, stationErr = phantomSelector.Select(seed, newGen, 0, true)
		func() {
			if errors.Is(clientErr, v0.ErrSubnetParseBug) {
				return // it is possible the errors don't match properly whe the client hits this bug
			} else if stationErr != nil && clientErr != nil {
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
		}()
	}
}
