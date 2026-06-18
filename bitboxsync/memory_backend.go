// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"sync"
)

// MemoryValueBackend stores typed collection values in memory.
//
// It is useful for tests, demos, and short-lived tools. Applications that need
// durable sync should provide a backend backed by their own storage.
type MemoryValueBackend[T any] struct {
	mu     sync.RWMutex
	values map[string]T
}

// NewMemoryValueBackend returns a RAM-backed ValueBackend initialized with a
// copy of initial.
func NewMemoryValueBackend[T any](initial map[string]T) *MemoryValueBackend[T] {
	return &MemoryValueBackend[T]{values: maps.Clone(initial)}
}

// Keys returns the stored keys in stable order.
func (b *MemoryValueBackend[T]) Keys(context.Context) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return slices.Sorted(maps.Keys(b.values)), nil
}

// Snapshot returns a shallow copy of all stored values.
func (b *MemoryValueBackend[T]) Snapshot(context.Context) (map[string]T, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return maps.Clone(b.values), nil
}

// Get returns the typed value for key.
func (b *MemoryValueBackend[T]) Get(_ context.Context, key string) (T, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	value, ok := b.values[key]
	if !ok {
		var zero T
		return zero, ErrNotFound
	}
	return value, nil
}

// Set stores the typed value for key.
func (b *MemoryValueBackend[T]) Set(_ context.Context, key string, value T) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.values == nil {
		b.values = make(map[string]T)
	}
	b.values[key] = value
	return nil
}

// SetIfCurrent atomically replaces key only when the stored value still matches
// the caller's last read.
func (b *MemoryValueBackend[T]) SetIfCurrent(_ context.Context, key string, current T, currentFound bool, value T) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	existing, ok := b.values[key]
	if ok != currentFound {
		return false, nil
	}
	if currentFound && !reflect.DeepEqual(existing, current) {
		return false, nil
	}
	if b.values == nil {
		b.values = make(map[string]T)
	}
	b.values[key] = value
	return true, nil
}
