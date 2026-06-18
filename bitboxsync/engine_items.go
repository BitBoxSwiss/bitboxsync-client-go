// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/BitBoxSwiss/bitboxsync-client-go/raw"
	"golang.org/x/crypto/chacha20poly1305"
)

type permanentUploadError struct {
	err error
}

func (e permanentUploadError) Error() string {
	return e.err.Error()
}

func (e permanentUploadError) Unwrap() error {
	return e.err
}

// syncNamespaceItems reconciles the remote item/version snapshot for a
// namespace against locally known items.
func (e *Engine) syncNamespaceItems(ctx context.Context, namespaceState NamespaceState, expectedHead uint64, scope namespaceActiveScope) error {
	state := e.identityStateSnapshot()
	resp, err := e.client.GetNamespaceItems(ctx, state.AccessToken, namespaceState.NamespaceID)
	if err != nil {
		return err
	}
	if resp.NamespaceHead < namespaceState.NamespaceHead {
		return fmt.Errorf("%w for namespace %s", ErrRollback, namespaceState.NamespaceID)
	}
	if resp.NamespaceHead < expectedHead {
		return fmt.Errorf("%w for namespace %s", ErrRollback, namespaceState.NamespaceID)
	}

	localItems, err := e.store.ListNamespaceItems(ctx, e.keyID, namespaceState.NamespaceID)
	if err != nil {
		return err
	}
	localByID := make(map[string]ItemState, len(localItems))
	inactiveByID := make(map[string]struct{})
	for _, item := range localItems {
		remoteItem, ok := resp.Items[item.ItemID]
		switch {
		case ok && remoteItem.Version < item.Version:
			return fmt.Errorf("%w for namespace %s item %s", ErrRollback, namespaceState.NamespaceID, item.ItemID)
		case !ok && item.Version > 0:
			return fmt.Errorf("%w for namespace %s item %s disappeared", ErrRollback, namespaceState.NamespaceID, item.ItemID)
		}
		if !scope.itemActive(item) {
			inactiveByID[item.ItemID] = struct{}{}
			continue
		}
		localByID[item.ItemID] = item
	}
	for itemID, item := range scope.activeItems {
		if _, ok := localByID[itemID]; !ok {
			localByID[itemID] = item
		}
	}

	for itemID, remoteItem := range resp.Items {
		localItem, ok := localByID[itemID]
		if !ok {
			if _, inactive := inactiveByID[itemID]; inactive {
				continue
			}
			e.emit(Event{
				Type:        EventUnknownRemoteItem,
				NamespaceID: namespaceState.NamespaceID,
				ItemID:      itemID,
			})
			continue
		}
		if remoteItem.Version <= localItem.Version {
			continue
		}
		if err := e.fetchAndApplyRemoteItem(ctx, namespaceState, localItem, remoteItem.Version); err != nil {
			return err
		}
	}

	namespaceState.NamespaceHead = resp.NamespaceHead
	namespaceState.ActiveScopeHash = scope.activeScopeHash
	namespaceState.UpdatedAt = time.Now().UTC()
	if resp.NamespaceHead < expectedHead {
		namespaceState.NamespaceHead = expectedHead
	}
	if err := e.store.SaveNamespace(ctx, namespaceState); err != nil {
		return err
	}
	e.emit(Event{
		Type:        EventNamespaceChanged,
		NamespaceID: namespaceState.NamespaceID,
	})
	return nil
}

// fetchAndApplyRemoteItem downloads one changed item and merges or stores it in
// local state.
func (e *Engine) fetchAndApplyRemoteItem(ctx context.Context, namespaceState NamespaceState, item ItemState, remoteVersion uint64) error {
	state := e.identityStateSnapshot()
	resp, err := e.client.GetItem(ctx, state.AccessToken, namespaceState.NamespaceID, item.ItemID)
	if err != nil {
		return err
	}
	if resp.Version < item.Version {
		return fmt.Errorf("%w for namespace %s item %s", ErrRollback, namespaceState.NamespaceID, item.ItemID)
	}
	remoteValue, err := e.decryptRemoteItem(namespaceState, item.ItemID, resp)
	if err != nil {
		return err
	}
	actualRemoteVersion := resp.Version
	if actualRemoteVersion < remoteVersion {
		return fmt.Errorf("%w for namespace %s item %s", ErrRollback, namespaceState.NamespaceID, item.ItemID)
	}
	return e.withLogicalKeyLock(item.NamespaceID, item.Collection, item.Key, func() error {
		currentItem, err := e.store.GetItemByID(ctx, e.keyID, item.NamespaceID, item.ItemID)
		switch {
		case err == nil:
			item = currentItem
		case errors.Is(err, ErrNotFound):
			if item.KeyID == "" {
				return nil
			}
		default:
			return err
		}
		if item.Version >= actualRemoteVersion {
			return nil
		}
		return e.applyRemoteValueLocked(ctx, namespaceState, item, actualRemoteVersion, remoteValue)
	})
}

// applyRemoteValueLocked merges or stores one downloaded remote value. The
// caller must hold the logical-key lock for item.
func (e *Engine) applyRemoteValueLocked(ctx context.Context, namespaceState NamespaceState, item ItemState, remoteVersion uint64, remoteValue []byte) error {
	if item.Conflict {
		markItemConflict(&item, remoteVersion, remoteValue)
		if err := e.store.SaveItem(ctx, item); err != nil {
			return err
		}
		e.emitItem(item, EventConflictDetected)
		return nil
	}

	var localValue []byte
	var haveLocalValue bool
	if !item.Dirty {
		// Clean sync metadata is only a statement about the last snapshot
		// reconciliation, which ran earlier in the sync pass. App-owned storage
		// can still be written directly after that snapshot. Re-read the backend
		// while holding this item's logical-key lock before applying remote data:
		// if the value no longer matches the stored clean base, promote it to a
		// dirty local edit and use the normal merge/conflict path below.
		var err error
		localValue, err = e.itemCurrentValue(ctx, item)
		switch {
		case err == nil:
			haveLocalValue = true
			if hasMergeBase(item) && bytes.Equal(localValue, item.BaseValue) {
				return e.applyCleanRemoteValue(ctx, item, remoteVersion, remoteValue, localValue, true)
			}
			markItemDirty(&item)
		case errors.Is(err, ErrNotFound):
			// There is no local value to protect. This is the normal remote-only
			// onboarding path for newly active keys.
			return e.applyCleanRemoteValue(ctx, item, remoteVersion, remoteValue, nil, false)
		default:
			return err
		}
	}

	if !haveLocalValue {
		var err error
		localValue, err = e.itemCurrentValue(ctx, item)
		if err != nil {
			return err
		}
	}
	if bytes.Equal(localValue, remoteValue) {
		return e.applyCleanRemoteValue(ctx, item, remoteVersion, remoteValue, localValue, true)
	}

	var baseValue *[]byte
	if hasMergeBase(item) {
		base := bytes.Clone(item.BaseValue)
		baseValue = &base
	}
	mergedValue, resolved, err := e.applyMerge(namespaceState.NamespaceID, item.Collection, item.Key, baseValue, localValue, remoteValue)
	if err != nil {
		return err
	}
	if resolved {
		replaced, err := e.setItemCurrentValueIfCurrent(ctx, &item, localValue, true, mergedValue)
		if err != nil {
			return err
		}
		if !replaced {
			return e.keepDirtyAfterValueRace(ctx, item)
		}
		if bytes.Equal(mergedValue, remoteValue) {
			markItemClean(&item, remoteVersion, remoteValue)
		} else {
			markItemDirtyWithBase(&item, remoteVersion, remoteValue)
		}
	} else {
		markItemConflict(&item, remoteVersion, remoteValue)
	}
	if err := e.store.SaveItem(ctx, item); err != nil {
		return err
	}

	eventType := EventItemChanged
	if item.Conflict {
		eventType = EventConflictDetected
	}
	e.emitItem(item, eventType)
	return nil
}

func (e *Engine) applyCleanRemoteValue(
	ctx context.Context,
	item ItemState,
	remoteVersion uint64,
	remoteValue []byte,
	currentValue []byte,
	currentFound bool,
) error {
	replaced, err := e.setItemCurrentValueIfCurrent(ctx, &item, currentValue, currentFound, remoteValue)
	if err != nil {
		return err
	}
	if !replaced {
		return e.keepDirtyAfterValueRace(ctx, item)
	}
	markItemClean(&item, remoteVersion, remoteValue)
	if err := e.store.SaveItem(ctx, item); err != nil {
		return err
	}
	e.emitItem(item, EventItemChanged)
	e.emitItem(item, EventItemDownloaded)
	return nil
}

func (e *Engine) keepDirtyAfterValueRace(ctx context.Context, item ItemState) error {
	// A conditional backend write failed because app storage changed after sync
	// read it. Do not apply the stale remote/merged value over that app write.
	// Leaving the item dirty makes the current backend value go through the
	// normal upload path, where an If-Match failure will fetch and merge the
	// remote version again.
	markItemDirty(&item)
	if err := e.store.SaveItem(ctx, item); err != nil {
		return err
	}
	e.emitItem(item, EventItemQueued)
	return nil
}

// flushDirtyItems uploads queued local writes in update order.
func (e *Engine) flushDirtyItems(ctx context.Context) error {
	state := e.identityStateSnapshot()
	dirtyItems, err := e.store.ListDirtyItems(ctx, e.keyID)
	if err != nil {
		return err
	}
	sort.Slice(dirtyItems, func(i, j int) bool {
		return dirtyItems[i].UpdatedAt.Before(dirtyItems[j].UpdatedAt)
	})

	namespaceCache := make(map[string]NamespaceState)
	scopeCache := make(map[string]namespaceActiveScope)
	for _, item := range dirtyItems {
		namespaceState, ok := namespaceCache[item.NamespaceID]
		if !ok {
			namespaceState, err = e.ensureNamespaceReady(ctx, item.NamespaceID, "")
			if err != nil {
				return err
			}
			namespaceCache[item.NamespaceID] = namespaceState
		}
		scope, ok := scopeCache[item.NamespaceID]
		if !ok {
			scope, err = e.loadActiveScope(ctx, namespaceState)
			if err != nil {
				return err
			}
			scopeCache[item.NamespaceID] = scope
		}
		if !scope.itemActive(item) {
			continue
		}
		if err := e.withLogicalKeyLock(item.NamespaceID, item.Collection, item.Key, func() error {
			currentItem, err := e.store.GetItemByID(ctx, e.keyID, item.NamespaceID, item.ItemID)
			switch {
			case err == nil:
				item = currentItem
			case errors.Is(err, ErrNotFound):
				return nil
			default:
				return err
			}
			if item.Conflict || !item.Dirty || !scope.itemActive(item) {
				return nil
			}
			// Keep the upload mechanics in one place because a precondition
			// failure can produce a resolved merge that should be uploaded
			// immediately with the freshly fetched remote version as its base.
			upload := func(item ItemState) (*protocol.PutItemResponse, []byte, error) {
				targetVersion := uint64(1)
				var ifMatch *uint64
				if item.Version > 0 {
					targetVersion = item.Version + 1
					ifMatch = &item.Version
				}
				uploadValue, err := e.itemCurrentValue(ctx, item)
				if err != nil {
					if errors.Is(err, ErrNotFound) {
						return nil, nil, permanentUploadError{
							err: fmt.Errorf("dirty item %s/%s has no current value: %w", item.Collection, item.Key, err),
						}
					}
					return nil, nil, err
				}
				if err := validateUploadValueSize(item, uploadValue); err != nil {
					return nil, nil, permanentUploadError{err: err}
				}
				nonce, aad, ciphertext, err := protocol.EncryptItem(item.NamespaceID, item.ItemID, targetVersion, namespaceState.DEK, uploadValue)
				if err != nil {
					return nil, nil, err
				}
				resp, err := e.client.PutItem(ctx, state.AccessToken, item.NamespaceID, item.ItemID, protocol.PutItemRequest{
					Nonce:      protocol.EncodeBase64(nonce),
					AAD:        protocol.EncodeBase64(aad),
					Ciphertext: protocol.EncodeBase64(ciphertext),
				}, ifMatch)
				return resp, uploadValue, err
			}
			// Mark the value clean only after the server accepted exactly the
			// plaintext that was encrypted for this upload attempt.
			saveUpload := func(resp *protocol.PutItemResponse, uploadValue []byte) error {
				markItemClean(&item, resp.Version, uploadValue)
				if err := e.store.SaveItem(ctx, item); err != nil {
					return err
				}
				namespaceState.NamespaceHead++
				namespaceState.UpdatedAt = time.Now().UTC()
				if err := e.store.SaveNamespace(ctx, namespaceState); err != nil {
					return err
				}
				namespaceCache[item.NamespaceID] = namespaceState
				e.emitItem(item, EventItemUploaded)
				return nil
			}

			resp, uploadValue, err := upload(item)
			if err == nil {
				return saveUpload(resp, uploadValue)
			}
			var permanentErr permanentUploadError
			if errors.As(err, &permanentErr) {
				return nil
			}
			if isPreconditionError(err) {
				if err := e.fetchAndApplyRemoteItemForConflictLocked(ctx, namespaceState, item); err != nil {
					return err
				}
				// The conflict fetch may have resolved by writing a merged value
				// and marking the item dirty with the remote version as the new
				// base. Reload before deciding whether there is anything safe to
				// retry.
				currentItem, err := e.store.GetItemByID(ctx, e.keyID, item.NamespaceID, item.ItemID)
				switch {
				case err == nil:
					item = currentItem
				case errors.Is(err, ErrNotFound):
					return nil
				default:
					return err
				}
				if item.Conflict || !item.Dirty || !scope.itemActive(item) {
					return nil
				}
				// Retry once. A second precondition failure means another writer
				// raced this merge too, so leave the item dirty for a later pass
				// instead of looping inside one flush.
				resp, uploadValue, err = upload(item)
				if err == nil {
					return saveUpload(resp, uploadValue)
				}
				if errors.As(err, &permanentErr) {
					return nil
				}
				if isPreconditionError(err) {
					// Refresh once more so the next sync pass starts from the
					// latest known remote base. Do not retry again here.
					if err := e.fetchAndApplyRemoteItemForConflictLocked(ctx, namespaceState, item); err != nil {
						return err
					}
					return nil
				}
			}
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

func isPreconditionError(err error) bool {
	var apiErr *raw.APIError
	return errors.As(err, &apiErr) && (apiErr.StatusCode == 412 || apiErr.StatusCode == 428)
}

func validateUploadValueSize(item ItemState, uploadValue []byte) error {
	if len(uploadValue) > protocol.MaxItemCiphertextSize-chacha20poly1305.Overhead {
		ciphertextSize := len(uploadValue) + chacha20poly1305.Overhead
		return fmt.Errorf(
			"dirty item %s/%s ciphertext would be %d bytes, max %d",
			item.Collection,
			item.Key,
			ciphertextSize,
			protocol.MaxItemCiphertextSize,
		)
	}
	return nil
}

// fetchAndApplyRemoteItemForConflict refreshes remote state after a failed write
// precondition and then merges or records a conflict.
func (e *Engine) fetchAndApplyRemoteItemForConflictLocked(ctx context.Context, namespaceState NamespaceState, item ItemState) error {
	state := e.identityStateSnapshot()
	resp, err := e.client.GetItem(ctx, state.AccessToken, namespaceState.NamespaceID, item.ItemID)
	if err != nil {
		return err
	}
	if resp.Version < item.Version {
		return fmt.Errorf("%w for namespace %s item %s", ErrRollback, namespaceState.NamespaceID, item.ItemID)
	}
	remoteValue, err := e.decryptRemoteItem(namespaceState, item.ItemID, resp)
	if err != nil {
		return err
	}
	return e.applyRemoteValueLocked(ctx, namespaceState, item, resp.Version, remoteValue)
}

// decryptRemoteItem validates AAD and decrypts one item response.
func (e *Engine) decryptRemoteItem(namespaceState NamespaceState, itemID string, resp *protocol.GetItemResponse) ([]byte, error) {
	nonce, err := protocol.DecodeBase64Exact("nonce", resp.Nonce, protocol.ItemNonceLength)
	if err != nil {
		return nil, err
	}
	aad, err := protocol.DecodeBase64("aad", resp.AAD)
	if err != nil {
		return nil, err
	}
	ciphertext, err := protocol.DecodeBase64("ciphertext", resp.Ciphertext)
	if err != nil {
		return nil, err
	}
	if err := protocol.VerifyAAD(namespaceState.NamespaceID, itemID, resp.Version, aad); err != nil {
		return nil, err
	}
	return protocol.DecryptItem(namespaceState.DEK, nonce, aad, ciphertext)
}

func hasMergeBase(item ItemState) bool {
	return item.BaseVersion != 0 || len(item.BaseValue) != 0
}

func markItemClean(item *ItemState, version uint64, baseValue []byte) {
	item.Version = version
	item.BaseVersion = version
	item.BaseValue = bytes.Clone(baseValue)
	item.Dirty = false
	clearItemConflict(item)
	touchItem(item)
}

func markItemDirty(item *ItemState) {
	item.Dirty = true
	touchItem(item)
}

func markItemDirtyWithBase(item *ItemState, version uint64, baseValue []byte) {
	item.Version = version
	item.BaseVersion = version
	item.BaseValue = bytes.Clone(baseValue)
	item.Dirty = true
	clearItemConflict(item)
	touchItem(item)
}

func markItemConflict(item *ItemState, remoteVersion uint64, remoteValue []byte) {
	item.Version = remoteVersion
	item.Dirty = true
	item.Conflict = true
	item.ConflictRemoteVersion = remoteVersion
	item.ConflictRemoteValue = bytes.Clone(remoteValue)
	touchItem(item)
}

func clearItemConflict(item *ItemState) {
	item.Conflict = false
	item.ConflictRemoteVersion = 0
	item.ConflictRemoteValue = nil
}

func touchItem(item *ItemState) {
	item.UpdatedAt = time.Now().UTC()
}

func (e *Engine) itemCurrentValue(ctx context.Context, item ItemState) ([]byte, error) {
	collection, ok := e.collectionRegistration(item.NamespaceID, item.Collection)
	if !ok {
		return nil, fmt.Errorf("%w for collection %q", ErrNoBackend, item.Collection)
	}
	value, err := collection.get(ctx, item.Key)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(value), nil
}

// setItemCurrentValueIfCurrent stores value only if the backend still contains
// the value that was read earlier in the same locked sync step. App-owned
// backends that implement ConditionalValueBackend can reject the write when a
// direct app write raced with remote apply; backends without that extension fall
// back to the plain Set behavior.
func (e *Engine) setItemCurrentValueIfCurrent(
	ctx context.Context,
	item *ItemState,
	current []byte,
	currentFound bool,
	value []byte,
) (bool, error) {
	collection, ok := e.collectionRegistration(item.NamespaceID, item.Collection)
	if !ok {
		return false, fmt.Errorf("%w for collection %q", ErrNoBackend, item.Collection)
	}
	return collection.setIfCurrent(ctx, item.Key, bytes.Clone(current), currentFound, bytes.Clone(value))
}

func (e *Engine) withLogicalKeyLock(namespaceID, collection, key string, fn func() error) error {
	lockKey := joinKeyParts(namespaceID, collection, key)
	value, _ := e.logicalKeyLocks.LoadOrStore(lockKey, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	return fn()
}
