// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sort"

	"bitboxsync-client-go/protocol"
)

type namespaceActiveScope struct {
	scopedCollections map[string]struct{}
	activeItemIDs     map[string]struct{}
	activeItems       map[string]ItemState
	activeScopeHash   string
}

func (s namespaceActiveScope) itemActive(item ItemState) bool {
	if _, scoped := s.scopedCollections[item.Collection]; !scoped {
		return false
	}
	_, active := s.activeItemIDs[item.ItemID]
	return active
}

func (s namespaceActiveScope) computeHash() string {
	if len(s.scopedCollections) == 0 {
		return ""
	}
	hash := sha256.New()
	hash.Write([]byte("bitboxsync-active-scope-v1"))
	collections := slices.Sorted(maps.Keys(s.scopedCollections))
	for _, collection := range collections {
		hash.Write([]byte{0})
		hash.Write([]byte(collection))
	}
	itemIDs := slices.Sorted(maps.Keys(s.activeItemIDs))
	for _, itemID := range itemIDs {
		hash.Write([]byte{1})
		hash.Write([]byte(itemID))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// loadActiveScope maps app-owned logical keys to item IDs before remote
// reconciliation. The returned scope is the set of registered collection keys
// that should participate in this sync pass.
func (e *Engine) loadActiveScope(ctx context.Context, namespaceState NamespaceState) (namespaceActiveScope, error) {
	registered := e.collectionRegistrations(namespaceState.NamespaceID)
	scope := namespaceActiveScope{
		scopedCollections: map[string]struct{}{},
		activeItemIDs:     map[string]struct{}{},
		activeItems:       map[string]ItemState{},
	}
	for _, collection := range registered {
		scope.scopedCollections[collection.name] = struct{}{}
		keys, err := collection.keys(ctx)
		if err != nil {
			return namespaceActiveScope{}, err
		}
		keys = uniqueSortedStrings(keys)
		for _, key := range keys {
			itemID, err := protocol.ItemID(namespaceState.DEK, composeLogicalKey(collection.name, key))
			if err != nil {
				return namespaceActiveScope{}, err
			}
			scope.activeItemIDs[itemID] = struct{}{}
			scope.activeItems[itemID] = ItemState{
				KeyID:       e.keyID,
				NamespaceID: namespaceState.NamespaceID,
				Collection:  collection.name,
				Key:         key,
				ItemID:      itemID,
			}
		}
	}
	scope.activeScopeHash = scope.computeHash()
	return scope, nil
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := slices.Clone(values)
	sort.Strings(out)
	return slices.Compact(out)
}

// collectionRegistrations returns the registered collections for one namespace.
func (e *Engine) collectionRegistrations(namespaceID string) []registeredCollection {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]registeredCollection, 0)
	for _, key := range slices.Sorted(maps.Keys(e.collections)) {
		collection := e.collections[key]
		if collection.namespaceID == namespaceID {
			out = append(out, collection)
		}
	}
	return out
}

// registeredCollections returns all collection registrations in stable order.
func (e *Engine) registeredCollections() []registeredCollection {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]registeredCollection, 0, len(e.collections))
	for _, key := range slices.Sorted(maps.Keys(e.collections)) {
		out = append(out, e.collections[key])
	}
	return out
}

// applyMerge dispatches to the registered collection merge policy.
func (e *Engine) applyMerge(namespaceID, collection, key string, base *[]byte, local, remote []byte) ([]byte, bool, error) {
	handler, ok := e.collectionRegistration(namespaceID, collection)
	if !ok || handler.mergeBytes == nil {
		out := bytes.Clone(local)
		return out, false, nil
	}
	return handler.mergeBytes(key, base, local, remote)
}

// collectionRegistration returns the registered collection hooks, if any.
func (e *Engine) collectionRegistration(namespaceID, collection string) (registeredCollection, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	handler, ok := e.collections[collectionRegistryKey(namespaceID, collection)]
	if !ok {
		return registeredCollection{}, false
	}
	return handler, true
}

// registerCollection records one collection's active-scope, value, and merge
// handlers for one namespace.
func (e *Engine) registerCollection(registration registeredCollection) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := collectionRegistryKey(registration.namespaceID, registration.name)
	if _, exists := e.collections[key]; exists {
		return fmt.Errorf("%w: namespace %s collection %q", ErrCollectionRegistered, registration.namespaceID, registration.name)
	}
	e.collections[key] = registration
	return nil
}

// collectionRegistryKey returns the map key used for collection registrations.
func collectionRegistryKey(namespaceID, collection string) string {
	return joinKeyParts(namespaceID, collection)
}

// composeLogicalKey joins a collection name and logical key into the namespace-
// scoped logical-key string used for item ID derivation.
func composeLogicalKey(collection, key string) string {
	return joinKeyParts(collection, key)
}

func joinKeyParts(parts ...string) string {
	var out []byte
	for _, part := range parts {
		out = binary.BigEndian.AppendUint64(out, uint64(len(part)))
		out = append(out, part...)
	}
	return string(out)
}

// cloneBytes returns a copy of value.
