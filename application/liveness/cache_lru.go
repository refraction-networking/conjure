package liveness

import (
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

const defaultSizeLRU = 100000

type lruCache struct {
	ipCache    map[string]*cacheElement
	lru        *lru.Cache
	lruSize    int
	expiration time.Duration
	m          sync.RWMutex
}

func newLRUCache(exp time.Duration, size int) *lruCache {

	lc := &lruCache{
		ipCache:    make(map[string]*cacheElement),
		lruSize:    size,
		expiration: exp,
	}

	// If an address is evicted from the LRU Cache remove it from the liveness map
	onEvict := func(k, v interface{}) {
		lc.m.Lock()
		defer lc.m.Unlock()

		key := k.(string)
		delete(lc.ipCache, key)
	}
	if lc.lruSize <= 0 {
		lc.lruSize = defaultSizeLRU
	}
	lruCache, err := lru.NewWithEvict(lc.lruSize, onEvict)
	if err != nil {
		return nil
	}

	lc.lru = lruCache

	return lc
}

func (lc *lruCache) Lookup(key string) bool {
	lc.m.RLock()
	elem, ok := lc.ipCache[key]
	lc.m.RUnlock()

	if ok && time.Since(elem.cachedTime) < lc.expiration {
		// refresh this address in the LRU cache
		lc.lru.Add(key, struct{}{})
	} else if ok && time.Since(elem.cachedTime) >= lc.expiration {
		return false
	}

	return ok
}

func (lc *lruCache) getExpired() []string {
	lc.m.RLock()
	defer lc.m.RUnlock()
	expired := []string{}

	for key, elem := range lc.ipCache {
		if time.Since(elem.cachedTime) > lc.expiration {
			// delete(lc.ipCache, key)
			expired = append(expired, key)
		}
	}

	return expired
}

func (lc *lruCache) ClearExpired() {
	expired := lc.getExpired()

	for _, key := range expired {
		// calls evict, removing from ipCache as well
		lc.lru.Remove(key)
	}
}

func (lc *lruCache) Add(key string, elem *cacheElement) {

	lc.m.Lock()
	lc.ipCache[key] = elem
	lc.m.Unlock()

	// add the address to the LRU cache - potentially evicting an entry
	lc.lru.Add(key, struct{}{})
}

func (lc *lruCache) Len() int {
	lc.m.RLock()
	defer lc.m.RUnlock()
	return len(lc.ipCache)
}

func (lc *lruCache) Cap() float64 {
	lc.m.RLock()
	defer lc.m.RUnlock()
	return float64(len(lc.ipCache)) / float64(lc.lruSize)
}
