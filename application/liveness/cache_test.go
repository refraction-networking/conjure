package liveness

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// func TestCachedLivenessLRU(t *testing.T) {
// 	clt := LRULivenessTester{
// 		lruSize: 3,
// 		stats:   &stats{},
// 	}
// 	err := clt.Init("1h")
// 	require.Nil(t, err)

// 	// Our three test cases are public DNS servers that implement DoH and DoT so
// 	// they should always have TCP 443 listening (Live). This test ensures that
// 	// even if we have 4 live hosts only 3 end up in the cache due to the set
// 	// LRU capacity constraint. We also test that the LRU gets refreshed for a
// 	// key when an address is seen a second time.
// 	testCases := [...]struct {
// 		address string
// 		port    uint16
// 	}{
// 		{"8.8.8.8", 443},
// 		{"8.8.4.4", 443},
// 		{"1.1.1.1", 443},
// 		{"1.0.0.1", 443},
// 		{"8.8.4.4", 443},
// 	}

// 	for _, test := range testCases {
// 		liveness, _ := clt.PhantomIsLive(test.address, test.port)
// 		require.True(t, liveness, "received not live for: %s", test.address)
// 	}

// 	require.Equal(t, 3, len(clt.ipCache), "Incorrect number of entries in cache")

// 	oldest, _, ok := clt.lru.RemoveOldest()
// 	require.True(t, ok)
// 	require.Equal(t, "1.1.1.1", oldest.(string))
// }

func TestLivenessCacheLRU(t *testing.T) {
	lru := newLRUCache(5*time.Second, 3)

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		for range ticker.C {
			lru.ClearExpired()
		}
	}()

	// test that inserting past capacity evicts from map cache
	lru.Add("key1", &cacheElement{cachedTime: time.Now()})
	lru.Add("key2", &cacheElement{cachedTime: time.Now()})
	lru.Add("key3", &cacheElement{cachedTime: time.Now()})
	lru.Add("key4", &cacheElement{cachedTime: time.Now()})

	require.Equal(t, 3, len(lru.ipCache), "Incorrect number of entries in cache")

	time.Sleep(2 * time.Second)

	// Test that the LRU gets refreshed for a key when an address is seen a
	// second time.
	lru.Add("key2", &cacheElement{cachedTime: time.Now()})
	oldest, _, ok := lru.lru.GetOldest()
	require.True(t, ok)
	require.Equal(t, "key3", oldest.(string))

	// test that lookup refreshes keys in the lru without refreshing the timeout
	//   - we access key 3 making key 4 the oldest
	ok = lru.Lookup("key3")
	require.True(t, ok)
	oldest, _, ok = lru.lru.GetOldest()
	require.True(t, ok)
	require.Equal(t, "key4", oldest.(string))

	time.Sleep(4 * time.Second)

	// Test that the elements added initially are cleared due to expiration time
	require.Equal(t, lru.Len(), 1)
	oldest, _, ok = lru.lru.GetOldest()
	require.True(t, ok)
	require.Equal(t, "key2", oldest.(string))
}

func TestLivenessCacheMap(t *testing.T) {
	mc := newMapCache(5 * time.Second)

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		for range ticker.C {
			mc.ClearExpired()
		}
	}()

	// test that inserting works (no capacity limit)
	mc.Add("key1", &cacheElement{cachedTime: time.Now()})
	mc.Add("key2", &cacheElement{cachedTime: time.Now()})
	mc.Add("key3", &cacheElement{cachedTime: time.Now()})
	mc.Add("key4", &cacheElement{cachedTime: time.Now()})

	require.Equal(t, 4, len(mc.ipCache), "Incorrect number of entries in cache")

	time.Sleep(2 * time.Second)

	// Since key 2 is already present it should not be added again, but key 5
	// will be added fresh
	mc.Add("key2", &cacheElement{cachedTime: time.Now()})
	mc.Add("key5", &cacheElement{cachedTime: time.Now()})

	// Lookup works (doesn't effect cache or timeout)
	ok := mc.Lookup("key1")
	require.True(t, ok)
	ok = mc.Lookup("key0")
	require.False(t, ok)

	time.Sleep(4 * time.Second)

	// Keys 1-4 should timeout leaving key 5
	require.Equal(t, 1, mc.Len())
}

// TestLivenessCacheLookupTimedOut ensures that even if stale cache entries
// haven't been removed / evicted yet, they don't return a "cached" result on
// lookup.
func TestLivenessCacheLookupTimedOut(t *testing.T) {

	mc := newMapCache(2 * time.Second)
	lru := newLRUCache(2*time.Second, 3)

	// test that inserting works (no capacity limit)
	mc.Add("key1", &cacheElement{cachedTime: time.Now()})
	lru.Add("key1", &cacheElement{cachedTime: time.Now()})

	time.Sleep(2500 * time.Millisecond)

	ok := mc.Lookup("key1")
	require.False(t, ok)

	ok = lru.Lookup("key1")
	require.False(t, ok)
}
