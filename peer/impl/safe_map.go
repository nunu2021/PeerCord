package impl

import (
	"sync"
)

// Basic thread-safe (T -> U) map
type safeMap[T comparable, U any] struct {
	mutex sync.Mutex
	data  map[T]U
}

func newSafeMap[T comparable, U any]() safeMap[T, U] {
	return safeMap[T, U]{
		data: make(map[T]U),
	}
}

// Safely get a value of the map
func (sm *safeMap[T, U]) get(key T) (U, bool) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	val, exists := sm.data[key]
	return val, exists
}

// Safely set a value of the map
func (sm *safeMap[T, U]) set(key T, val U) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// TODO allow deleting an entry
	/*if val == "" { // Delete the entry
		delete(srt.data, key)
	} else {
		srt.data[key] = val
	}*/

	sm.data[key] = val
}

// Returns the internal map. It is not thread-safe.
func (sm *safeMap[T, U]) internalMap() map[T]U {
	return sm.data
}

// Returns a copy of the internal routing table
func (sm *safeMap[T, U]) clone() map[T]U {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	newMap := make(map[T]U)
	for key, val := range sm.data {
		newMap[key] = val
	}

	return newMap
}
