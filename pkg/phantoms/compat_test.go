package phantoms

import (
	"crypto/rand"
	"os"
	"testing"

	v0 "github.com/refraction-networking/conjure/internal/compatability/v0"
	v1 "github.com/refraction-networking/conjure/internal/compatability/v1"
	"github.com/refraction-networking/conjure/pkg/core"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

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
		clientSelectedPhantom4, err := v1.SelectPhantom(seed, psl, v1.V4Only, true)
		require.Nil(t, err)

		phantomAddr, err := phantomSelector.Select(seed, newGen, core.PhantomSelectionMinGeneration, false)
		require.Nil(t, err)
		require.Equal(t, clientSelectedPhantom4.String(), phantomAddr.String())

		_, err = rand.Read(seed)
		require.Nil(t, err)
		clientSelectedPhantom6, err := v1.SelectPhantom(seed, psl, v1.V6Only, true)
		require.Nil(t, err)

		phantomAddr6, err := phantomSelector.Select(seed, newGen, core.PhantomSelectionMinGeneration, false)
		require.Nil(t, err)
		require.Equal(t, clientSelectedPhantom6.String(), phantomAddr6.String())
	}
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
		clientSelectedPhantom4, err := v0.SelectPhantom(seed, psl, v0.V4Only, true)
		require.Nil(t, err)

		phantomAddr, err := phantomSelector.Select(seed, newGen, 0, false)
		require.Nil(t, err)
		require.Equal(t, clientSelectedPhantom4.String(), phantomAddr.String())

		_, err = rand.Read(seed)
		require.Nil(t, err)
		clientSelectedPhantom6, err := v0.SelectPhantom(seed, psl, v0.V6Only, true)
		require.Nil(t, err)

		phantomAddr6, err := phantomSelector.Select(seed, newGen, 0, false)
		require.Nil(t, err)
		require.Equal(t, clientSelectedPhantom6.String(), phantomAddr6.String())
	}
}
