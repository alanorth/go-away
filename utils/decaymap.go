package utils

import (
	"sync"
	"time"
)

func zilch[T any]() T {
	var zero T
	return zero
}

type DecayMap[K comparable, V any] struct {
	data map[K]DecayMapEntry[V]
	lock sync.RWMutex
}

type DecayMapEntry[V any] struct {
	Value  V
	expiry time.Time
}

func NewDecayMap[K comparable, V any]() *DecayMap[K, V] {
	return &DecayMap[K, V]{
		data: make(map[K]DecayMapEntry[V]),
	}
}

func (m *DecayMap[K, V]) Get(key K) (V, bool) {
	m.lock.RLock()
	value, ok := m.data[key]
	m.lock.RUnlock()

	if !ok {
		return zilch[V](), false
	}

	if time.Now().After(value.expiry) {
		m.lock.Lock()
		// Since previously reading m.data[key], the value may have been updated.
		// Delete the entry only if the expiry time is still the same.
		if m.data[key].expiry == value.expiry {
			delete(m.data, key)
		}
		m.lock.Unlock()

		return zilch[V](), false
	}

	return value.Value, true
}

func (m *DecayMap[K, V]) Set(key K, value V, ttl time.Duration) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.data[key] = DecayMapEntry[V]{
		Value:  value,
		expiry: time.Now().Add(ttl),
	}
}

func (m *DecayMap[K, V]) Decay() {
	m.lock.Lock()
	defer m.lock.Unlock()

	now := time.Now()
	for key, entry := range m.data {
		if now.After(entry.expiry) {
			delete(m.data, key)
		}
	}
}
