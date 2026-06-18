// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
)

// reconcileLocalSnapshots compares app-owned collection snapshots to the last
// clean values in sync metadata. New or changed snapshot values are marked dirty
// before the engine pulls remote state or flushes uploads.
func (e *Engine) reconcileLocalSnapshots(ctx context.Context) error {
	scopeCache := map[string]namespaceActiveScope{}
	for _, collection := range e.registeredCollections() {
		namespaceState, err := e.ensureNamespaceReady(ctx, collection.namespaceID, "")
		if err != nil {
			return err
		}
		values, err := collection.snapshot(ctx)
		if err != nil {
			return err
		}
		for _, key := range slices.Sorted(maps.Keys(values)) {
			itemID, err := protocol.ItemID(namespaceState.DEK, composeLogicalKey(collection.name, key))
			if err != nil {
				return err
			}
			scope, ok := scopeCache[collection.namespaceID]
			if !ok {
				scope, err = e.loadActiveScope(ctx, namespaceState)
				if err != nil {
					return err
				}
				scopeCache[collection.namespaceID] = scope
			}
			if !scope.itemActive(ItemState{
				NamespaceID: collection.namespaceID,
				Collection:  collection.name,
				Key:         key,
				ItemID:      itemID,
			}) {
				continue
			}
			item, queued, err := e.reconcileSnapshotValue(ctx, collection, key, itemID, values[key])
			if err != nil {
				return err
			}
			if queued {
				e.emitItem(item, EventItemQueued)
			}
		}
	}
	return nil
}

func (e *Engine) reconcileSnapshotValue(
	ctx context.Context,
	collection registeredCollection,
	key string,
	itemID string,
	value []byte,
) (ItemState, bool, error) {
	queued := false
	var queuedItem ItemState
	err := e.withLogicalKeyLock(collection.namespaceID, collection.name, key, func() error {
		item, err := e.store.GetItemByLogicalKey(ctx, e.keyID, collection.namespaceID, collection.name, key)
		switch {
		case err == nil:
		case errors.Is(err, ErrNotFound):
			item = ItemState{
				KeyID:       e.keyID,
				NamespaceID: collection.namespaceID,
				Collection:  collection.name,
				Key:         key,
				ItemID:      itemID,
			}
		default:
			return err
		}
		if item.ItemID == "" {
			item.ItemID = itemID
		}
		if item.Conflict || item.Dirty {
			return nil
		}
		if hasMergeBase(item) && bytes.Equal(value, item.BaseValue) {
			return nil
		}
		markItemDirty(&item)
		if err := e.store.SaveItem(ctx, item); err != nil {
			return err
		}
		queued = true
		queuedItem = item
		return nil
	})
	if err != nil {
		return ItemState{}, false, err
	}
	return queuedItem, queued, nil
}
