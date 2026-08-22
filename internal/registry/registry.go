// Package registry provides a concurrency-safe name-keyed store used for
// execution functions, state functions, and providers.
package registry

import (
	"fmt"
	"sort"
	"sync"
)

// Registry is a generic concurrency-safe name-keyed store.
// Registration happens at startup; lookups are lock-protected reads.
type Registry[T any] struct {
	mu    sync.RWMutex
	items map[string]T
}

// New creates an empty registry.
func New[T any]() *Registry[T] {
	return &Registry[T]{items: make(map[string]T)}
}

// Register adds item under name. Duplicate names are rejected so that
// accidental double registration fails fast at startup.
func (r *Registry[T]) Register(name string, item T) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.items[name]; dup {
		return fmt.Errorf("%q already registered", name)
	}
	r.items[name] = item
	return nil
}

// Get returns the item registered under name.
func (r *Registry[T]) Get(name string) (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.items[name]
	return item, ok
}

// Len returns the number of registered items.
func (r *Registry[T]) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.items)
}

// Names returns all registered names sorted lexicographically.
func (r *Registry[T]) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.items))
	for name := range r.items {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
