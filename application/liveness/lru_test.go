package liveness

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCachedLivenessLRU(t *testing.T) {
	clt := LRULivenessTester{
		lruSize: 3,
		stats:   &stats{},
	}
	err := clt.Init("1h")
	require.Nil(t, err)

	// Our three test cases are public DNS servers that implement DoH and DoT so
	// they should always have TCP 443 listening (Live). This test ensures that
	// even if we have 4 live hosts only 3 end up in the cache due to the set
	// LRU capacity constraint. We also test that the LRU gets refreshed for a
	// key when an address is seen a second time.
	testCases := [...]struct {
		address string
		port    uint16
	}{
		{"8.8.8.8", 443},
		{"8.8.4.4", 443},
		{"1.1.1.1", 443},
		{"1.0.0.1", 443},
		{"8.8.4.4", 443},
	}

	for _, test := range testCases {
		liveness, _ := clt.PhantomIsLive(test.address, test.port)
		require.True(t, liveness, "received not live for: %s", test.address)
	}

	require.Equal(t, 3, len(clt.ipCache), "Incorrect number of entries in cache")

	oldest, _, ok := clt.lru.RemoveOldest()
	require.True(t, ok)
	require.Equal(t, "1.1.1.1", oldest.(string))
}
