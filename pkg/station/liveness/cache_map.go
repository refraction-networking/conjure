package liveness

import (
	"sync"
	"time"
)

type mapCache struct {
	ipCache    map[string]*cacheElement
	expiration time.Duration
	m          sync.RWMutex
}

func newMapCache(exp time.Duration) *mapCache {
	return &mapCache{
		expiration: exp,
		ipCache:    make(map[string]*cacheElement),
	}
}

func (m *mapCache) Lookup(key string) bool {
	m.m.RLock()
	defer m.m.RUnlock()
	elem, ok := m.ipCache[key]
	if ok && time.Since(elem.cachedTime) >= m.expiration {
		return false
	}

	return ok
}

func (m *mapCache) ClearExpired() {
	if m == nil {
		return
	}

	m.m.Lock()
	defer m.m.Unlock()

	for ipAddr, status := range m.ipCache {
		if time.Since(status.cachedTime) > m.expiration {
			delete(m.ipCache, ipAddr)
		}
	}
}

func (m *mapCache) Add(key string, elem *cacheElement) {
	m.m.Lock()
	defer m.m.Unlock()
	// Do not overwrite if already in cache to prevent corner cases.
	if _, ok := m.ipCache[key]; !ok {
		m.ipCache[key] = elem
	}
}

func (m *mapCache) Len() int {
	m.m.RLock()
	defer m.m.RUnlock()
	return len(m.ipCache)
}

func (m *mapCache) Cap() float64 {
	return 0
}
