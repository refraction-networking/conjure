package lib

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPhantomsParse(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	conf, err := GetPhantomSubnetSelector()
	require.Nil(t, err)
	require.NotNil(t, conf)

	require.Equal(t, len(conf.Networks), 3)

	sc, ok := conf.Networks[957]
	require.Equal(t, ok, true)
	require.Equal(t, len(sc.WeightedSubnets), 2)
	require.Equal(t, len(sc.WeightedSubnets[0].Subnets), 2)
	require.Contains(t, sc.WeightedSubnets[0].Subnets, "192.122.190.0/24")
}
