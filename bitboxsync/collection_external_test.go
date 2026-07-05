// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/BitBoxSwiss/bitboxsync-client-go/raw"
	"github.com/stretchr/testify/require"
)

func TestSyncNamespacesReconcilesActiveScopeChangeAtCurrentHead(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := newFixedKeyBackend[string](nil, "reactivated")
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: backend,
	})
	require.NoError(t, err)
	namespaceState := setTestNamespaceHead(t, ctx, store, engine, namespace, 7)
	reactivated := saveTestItem(t, ctx, store, engine, namespace, "notes", "reactivated", ItemState{})
	itemResp := encryptedTestItemResponse(t, namespaceState, reactivated.ItemID, 1, []byte("remote note"))

	var namespaceItemsCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/mine":
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 7,
				}},
			})
		case "/v1/namespaces/" + namespace.ID() + "/items":
			namespaceItemsCalls++
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 7,
				Items: map[string]protocol.NamespaceItemVersion{
					reactivated.ItemID: {Version: 1},
				},
			})
		case "/v1/kv/" + namespace.ID() + "/" + reactivated.ItemID:
			writeTestJSON(t, w, itemResp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	// The namespace head is unchanged and the item metadata is already cached,
	// but the active key scope changed from the stored empty scope. Sync must
	// still fetch the item map and apply the remote value for the now-active key.
	require.NoError(t, engine.syncNamespaces(ctx))
	require.Equal(t, 1, namespaceItemsCalls)
	value, err := backend.Get(ctx, "reactivated")
	require.NoError(t, err)
	require.Equal(t, "remote note", value)
	namespaceState, err = store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	require.Equal(t, uint64(7), namespaceState.NamespaceHead)
	require.NotEmpty(t, namespaceState.ActiveScopeHash)

	// Once the same active scope has been checkpointed at the current namespace
	// head, the next sync can skip the item-version snapshot.
	require.NoError(t, engine.syncNamespaces(ctx))
	require.Equal(t, 1, namespaceItemsCalls)
}

func TestSyncNamespacesRejectsCachedNamespaceDisappearance(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestNamespaceHead(t, ctx, store, engine, namespace, 4)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/mine" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, protocol.ListNamespacesResponse{
			Namespaces: []protocol.NamespaceSummary{},
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	err := engine.syncNamespaces(ctx)
	require.ErrorIs(t, err, ErrRollback)
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	require.Equal(t, uint64(4), namespaceState.NamespaceHead)
}

func TestSyncNamespacesRejectsMultipleDefaultNamespaces(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	otherDefault := strings.Repeat("ab", protocol.NamespaceIDLength)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/mine" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, protocol.ListNamespacesResponse{
			Namespaces: []protocol.NamespaceSummary{
				{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 0,
				},
				{
					NamespaceID:   otherDefault,
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 0,
				},
			},
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	err := engine.syncNamespaces(ctx)
	require.ErrorContains(t, err, "multiple default namespaces")
}

func TestSyncNamespacesRejectsDefaultNamespaceMismatch(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	state := engine.identityStateSnapshot()
	state.DefaultNamespaceID = strings.Repeat("cd", protocol.NamespaceIDLength)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/mine" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, protocol.ListNamespacesResponse{
			Namespaces: []protocol.NamespaceSummary{{
				NamespaceID:   namespace.ID(),
				Kind:          protocol.NamespaceKindDefault,
				NamespaceHead: 0,
			}},
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	err := engine.syncNamespaces(ctx)
	require.ErrorIs(t, err, ErrRollback)
}

func TestCreateSharedNamespaceCachesDEK(t *testing.T) {
	ctx := context.Background()
	engine, store, _ := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestAccessToken(t, ctx, engine)

	var requests []protocol.CreateSharedNamespaceRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces", r.URL.Path)
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		var req protocol.CreateSharedNamespaceRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		requests = append(requests, req)
		writeTestJSON(t, w, protocol.CreateSharedNamespaceResponse{
			NamespaceID: req.NamespaceID,
			Kind:        protocol.NamespaceKindShared,
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	shared, err := engine.CreateSharedNamespace(ctx)
	require.NoError(t, err)
	require.Len(t, requests, 1)
	require.Equal(t, requests[0].NamespaceID, shared.ID())
	wrappedDEK, err := protocol.DecodeBase64("wrappedDek", requests[0].WrappedDEK)
	require.NoError(t, err)
	require.NoError(t, protocol.ValidateWrappedDEK(wrappedDEK))

	namespaceState, err := store.GetNamespace(ctx, engine.keyID, shared.ID())
	require.NoError(t, err)
	require.Equal(t, protocol.NamespaceKindShared, namespaceState.Kind)
	require.Len(t, namespaceState.DEK, protocol.NamespaceDEKLen)
}

func TestSyncNamespacesSkipsInactiveScopedItemsAndAdvancesHead(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := newFixedKeyBackend(map[string]string{
		"hidden": "old hidden note",
	}, "active")
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: backend,
	})
	require.NoError(t, err)
	setTestNamespaceHead(t, ctx, store, engine, namespace, 1)
	hidden := saveTestItem(t, ctx, store, engine, namespace, "notes", "hidden", ItemState{
		Version:   1,
		BaseValue: []byte("old hidden note"),
	})

	var namespaceItemsCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/mine":
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 2,
				}},
			})
		case "/v1/namespaces/" + namespace.ID() + "/items":
			namespaceItemsCalls++
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 2,
				Items: map[string]protocol.NamespaceItemVersion{
					hidden.ItemID: {Version: 2},
				},
			})
		case "/v1/kv/" + namespace.ID() + "/" + hidden.ItemID:
			require.Fail(t, "inactive item was downloaded")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	// The hidden key is cached locally, but the current key provider no longer
	// returns it. Sync skips the remote update and still advances the namespace
	// head because a later scope change will force reconciliation.
	require.NoError(t, engine.syncNamespaces(ctx))
	require.Equal(t, 1, namespaceItemsCalls)
	value, err := backend.Get(ctx, "hidden")
	require.NoError(t, err)
	require.Equal(t, "old hidden note", value)
	assertSameStoredItem(t, ctx, store, engine, namespace, "notes", "hidden", hidden)
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	require.Equal(t, uint64(2), namespaceState.NamespaceHead)
	require.False(t, hasEventType(drainEvents(engine), EventUnknownRemoteItem))
}

func TestSyncNamespacesRejectsInactiveItemDisappearance(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := newFixedKeyBackend(map[string]string{
		"hidden": "old hidden note",
	}, "active")
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: backend,
	})
	require.NoError(t, err)
	setTestNamespaceHead(t, ctx, store, engine, namespace, 1)
	hidden := saveTestItem(t, ctx, store, engine, namespace, "notes", "hidden", ItemState{
		Version:   1,
		BaseValue: []byte("old hidden note"),
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/mine":
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 2,
				}},
			})
		case "/v1/namespaces/" + namespace.ID() + "/items":
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 2,
				Items:         map[string]protocol.NamespaceItemVersion{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	err = engine.syncNamespaces(ctx)
	require.ErrorIs(t, err, ErrRollback)
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	require.Equal(t, uint64(1), namespaceState.NamespaceHead)
	assertSameStoredItem(t, ctx, store, engine, namespace, "notes", "hidden", hidden)
}

func TestSyncNamespacesSkipsUnregisteredCachedItems(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	setTestNamespaceHead(t, ctx, store, engine, namespace, 1)
	unregistered := saveTestItem(t, ctx, store, engine, namespace, "unopened", "key", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("cached value"),
	})

	var namespaceItemsCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/mine":
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 2,
				}},
			})
		case "/v1/namespaces/" + namespace.ID() + "/items":
			namespaceItemsCalls++
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 2,
				Items: map[string]protocol.NamespaceItemVersion{
					unregistered.ItemID: {Version: 2},
				},
			})
		case "/v1/kv/" + namespace.ID() + "/" + unregistered.ItemID:
			require.Fail(t, "unregistered item was downloaded")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.syncNamespaces(ctx))
	require.Equal(t, 1, namespaceItemsCalls)
	assertSameStoredItem(t, ctx, store, engine, namespace, "unopened", "key", unregistered)
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	require.Equal(t, uint64(2), namespaceState.NamespaceHead)
	require.False(t, hasEventType(drainEvents(engine), EventUnknownRemoteItem))
}

func TestFlushDirtyItemsSkipsUnregisteredCollections(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	dirty := saveTestItem(t, ctx, store, engine, namespace, "unopened", "key", ItemState{
		Dirty: true,
	})

	require.NoError(t, engine.flushDirtyItems(ctx))
	assertSameStoredItem(t, ctx, store, engine, namespace, "unopened", "key", dirty)
}

func TestFlushDirtyItemsSkipsOversizedValueAndContinues(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend(map[string]string{
		"too-big": strings.Repeat("x", protocol.MaxItemCiphertextSize),
		"ok":      "valid memo",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: backend,
	})
	require.NoError(t, err)
	tooBig := saveTestItem(t, ctx, store, engine, namespace, "notes", "too-big", ItemState{
		Dirty:     true,
		UpdatedAt: time.Unix(100, 0).UTC(),
	})
	ok := saveTestItem(t, ctx, store, engine, namespace, "notes", "ok", ItemState{
		Dirty:     true,
		UpdatedAt: time.Unix(200, 0).UTC(),
	})
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)

	var putCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v1/kv/"+namespace.ID()+"/"+tooBig.ItemID:
			require.Fail(t, "oversized item should not be uploaded")
		case r.Method == http.MethodPut && r.URL.Path == "/v1/kv/"+namespace.ID()+"/"+ok.ItemID:
			putCalls++
			require.Empty(t, r.Header.Get("If-Match"))
			plaintext := decryptTestPutItemRequest(t, namespaceState, ok.ItemID, 1, r)
			require.Equal(t, "valid memo", string(plaintext))
			writeTestJSON(t, w, protocol.PutItemResponse{
				NamespaceID: namespace.ID(),
				ItemID:      ok.ItemID,
				Version:     1,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.flushDirtyItems(ctx))
	require.Equal(t, 1, putCalls)

	storedTooBig, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "too-big")
	require.NoError(t, err)
	require.True(t, storedTooBig.Dirty)
	require.False(t, storedTooBig.Conflict)
	require.Zero(t, storedTooBig.Version)

	storedOK, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "ok")
	require.NoError(t, err)
	require.False(t, storedOK.Dirty)
	require.False(t, storedOK.Conflict)
	require.Equal(t, uint64(1), storedOK.Version)
}

func TestConflictStatePreservesOriginalMergeBase(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend(map[string]string{
		"same-key": "local edit",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   NoMerge[string](),
		Backend: backend,
	})
	require.NoError(t, err)
	namespaceState := setTestNamespaceHead(t, ctx, store, engine, namespace, 1)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "same-key", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("base value"),
		Dirty:       true,
	})
	itemResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 2, []byte("remote edit"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/"+namespace.ID()+"/"+item.ItemID || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, itemResp)
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	// The unresolved conflict needs both the current remote value/version for a
	// later If-Match upload and the original common base for UI/manual
	// resolution. The base must not be overwritten by the remote side.
	require.NoError(t, engine.fetchAndApplyRemoteItem(ctx, namespaceState, item, 2))
	value, err := backend.Get(ctx, "same-key")
	require.NoError(t, err)
	require.Equal(t, "local edit", value)
	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "same-key")
	require.NoError(t, err)
	require.True(t, stored.Dirty)
	require.True(t, stored.Conflict)
	require.Equal(t, uint64(2), stored.Version)
	require.Equal(t, uint64(1), stored.BaseVersion)
	require.Equal(t, "base value", string(stored.BaseValue))
	require.Equal(t, uint64(2), stored.ConflictRemoteVersion)
	require.Equal(t, "remote edit", string(stored.ConflictRemoteValue))
}

func TestFetchAndApplyRemoteItemUsesFetchedVersion(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend(map[string]string{
		"same-key": "base value",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferRemote[string](),
		Backend: backend,
	})
	require.NoError(t, err)
	namespaceState := setTestNamespaceHead(t, ctx, store, engine, namespace, 2)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "same-key", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("base value"),
	})
	itemResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 3, []byte("latest remote"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/"+namespace.ID()+"/"+item.ItemID || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, itemResp)
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	// The namespace item snapshot said version 2, but the item body fetched
	// immediately afterward is already version 3. The stored version must match
	// the AAD-verified item body so future If-Match writes are based on the value
	// actually stored as BaseValue.
	require.NoError(t, engine.fetchAndApplyRemoteItem(ctx, namespaceState, item, 2))
	value, err := backend.Get(ctx, "same-key")
	require.NoError(t, err)
	require.Equal(t, "latest remote", value)
	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "same-key")
	require.NoError(t, err)
	require.Equal(t, uint64(3), stored.Version)
	require.Equal(t, uint64(3), stored.BaseVersion)
	require.Equal(t, "latest remote", string(stored.BaseValue))
}

func TestSyncNamespaceItemsDetectsDisappearedKnownItemAsRollback(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: NewMemoryValueBackend[string](nil),
	})
	require.NoError(t, err)
	namespaceState := setTestNamespaceHead(t, ctx, store, engine, namespace, 4)
	known := saveTestItem(t, ctx, store, engine, namespace, "notes", "known", ItemState{
		Version:     2,
		BaseVersion: 2,
		BaseValue:   []byte("known remote value"),
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/"+namespace.ID()+"/items" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		// Regression coverage for rollback handling. Protocol-level deletion is
		// out of scope in v1, so an authoritative item-version snapshot that omits
		// an item this client previously saw at a nonzero version is stale or
		// malicious. The engine must reject the snapshot and keep its local
		// checkpoint unchanged instead of accepting the disappearance as the new
		// namespace truth.
		writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
			NamespaceID:   namespace.ID(),
			NamespaceHead: 5,
			Items:         map[string]protocol.NamespaceItemVersion{},
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	err = engine.syncNamespaceItems(ctx, namespaceState, 5, namespaceActiveScope{
		scopedCollections: map[string]struct{}{"notes": {}},
		activeItemIDs:     map[string]struct{}{known.ItemID: {}},
	})
	require.ErrorIs(t, err, ErrRollback)
	after, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	require.Equal(t, uint64(4), after.NamespaceHead)
	assertSameStoredItem(t, ctx, store, engine, namespace, "notes", "known", known)
}

func TestSyncNamespaceItemsRejectsSnapshotBehindExpectedHead(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	namespaceState := setTestNamespaceHead(t, ctx, store, engine, namespace, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/"+namespace.ID()+"/items" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
			NamespaceID:   namespace.ID(),
			NamespaceHead: 4,
			Items:         map[string]protocol.NamespaceItemVersion{},
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	err := engine.syncNamespaceItems(ctx, namespaceState, 5, namespaceActiveScope{})
	require.ErrorIs(t, err, ErrRollback)
	after, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	require.Equal(t, uint64(4), after.NamespaceHead)
}

func TestFlushDirtyItemsSkipsInactiveScopedItems(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: NewMemoryValueBackend[string](nil),
	})
	require.NoError(t, err)
	hidden := saveTestItem(t, ctx, store, engine, namespace, "notes", "hidden", ItemState{
		Version:   1,
		Dirty:     true,
		BaseValue: []byte("old hidden note"),
	})

	// Dirty cached keys outside the current active scope are left dirty and are
	// not uploaded until Backend.Keys returns them again.
	require.NoError(t, engine.flushDirtyItems(ctx))
	assertSameStoredItem(t, ctx, store, engine, namespace, "notes", "hidden", hidden)
}

func TestOpenCollectionRequiresValueBackend(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec: StringCodec(),
		Merge: PreferLocal[string](),
	})
	require.ErrorIs(t, err, ErrNoBackend)
}

func TestOpenCollectionRejectsDuplicateRegistration(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	firstBackend := NewMemoryValueBackend[string](nil)
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: firstBackend,
	})
	require.NoError(t, err)
	secondBackend := NewMemoryValueBackend[string](nil)
	_, err = OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: secondBackend,
	})
	require.ErrorIs(t, err, ErrCollectionRegistered)

	// The rejected registration must not replace the backend used by the sync
	// registry.
	require.NoError(t, firstBackend.Set(ctx, "same-key", "first backend value"))
	_, err = secondBackend.Get(ctx, "same-key")
	require.ErrorIs(t, err, ErrNotFound)
	encoded, err := engine.itemCurrentValue(ctx, ItemState{
		NamespaceID: namespace.ID(),
		Collection:  "notes",
		Key:         "same-key",
	})
	require.NoError(t, err)
	require.Equal(t, "first backend value", string(encoded))
}

func TestLogicalKeyCompositionIsLengthDelimited(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	_, err := OpenCollection(namespace, "a", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: NewMemoryValueBackend[string](nil),
	})
	require.NoError(t, err)
	_, err = OpenCollection(namespace, "a\x1fb", CollectionConfig[string]{
		Codec:   StringCodec(),
		Backend: NewMemoryValueBackend[string](nil),
	})
	require.NoError(t, err)

	// These two collection/key pairs both produced "a\x1fb\x1fc" under the old
	// separator-based composition. They must remain distinct so one item cannot
	// overwrite the other's metadata or encrypted remote value.
	saveTestItem(t, ctx, store, engine, namespace, "a", "b\x1fc", ItemState{})
	saveTestItem(t, ctx, store, engine, namespace, "a\x1fb", "c", ItemState{})
	leftItem, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "a", "b\x1fc")
	require.NoError(t, err)
	rightItem, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "a\x1fb", "c")
	require.NoError(t, err)
	require.NotEqual(t, leftItem.ItemID, rightItem.ItemID)
}

type fixedKeyBackend[T any] struct {
	*MemoryValueBackend[T]
	keys []string
}

func newFixedKeyBackend[T any](initial map[string]T, keys ...string) *fixedKeyBackend[T] {
	return &fixedKeyBackend[T]{
		MemoryValueBackend: NewMemoryValueBackend(initial),
		keys:               slices.Clone(keys),
	}
}

func (b *fixedKeyBackend[T]) Keys(context.Context) ([]string, error) {
	return slices.Clone(b.keys), nil
}

func TestCloseMakesLateSyncAndEmitSafe(t *testing.T) {
	ctx := context.Background()
	engine, _, _ := newTestEngine(t, ctx)

	require.NoError(t, engine.Close())
	require.ErrorIs(t, engine.SyncNow(ctx), ErrClosed)

	// Collection methods and in-flight sync cleanup can still attempt to emit
	// after Close has closed the public event stream. Emitting after close must
	// be a no-op rather than a send-on-closed-channel panic.
	defer func() {
		if recovered := recover(); recovered != nil {
			require.Failf(t, "emit after close panicked", "%v", recovered)
		}
	}()
	engine.emit(Event{Type: EventSyncFailed, Err: ErrClosed})
}

func newTestEngine(t *testing.T, ctx context.Context) (*Engine, *testStore, *Namespace) {
	t.Helper()

	client, err := raw.New("http://127.0.0.1:1", nil)
	require.NoError(t, err)
	identity, err := raw.NewDummyKeystore("test-key")
	require.NoError(t, err)
	store := newTestStore()
	engine, err := Open(ctx, Config{
		Client:   client,
		Identity: identity,
		Store:    store,
	})
	require.NoError(t, err)

	namespaceIDRaw, err := protocol.RandomNamespaceID()
	require.NoError(t, err)
	namespaceDEK, err := protocol.RandomNamespaceDEK()
	require.NoError(t, err)
	namespaceID := hex.EncodeToString(namespaceIDRaw)
	require.NoError(t, store.SaveNamespace(ctx, NamespaceState{
		KeyID:       engine.keyID,
		NamespaceID: namespaceID,
		Kind:        protocol.NamespaceKindDefault,
		DEK:         namespaceDEK,
		UpdatedAt:   time.Now().UTC(),
	}))
	return engine, store, &Namespace{engine: engine, namespaceID: namespaceID}
}

func closeTestEngine(t *testing.T, engine *Engine) {
	t.Helper()
	require.NoError(t, engine.Close())
}

func setTestAccessToken(t *testing.T, ctx context.Context, engine *Engine) {
	t.Helper()

	state := engine.identityStateSnapshot()
	state.AccessToken = "test-token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	state.UpdatedAt = time.Now().UTC()
	require.NoError(t, engine.saveIdentityState(ctx, state))
}

func setTestNamespaceKind(t *testing.T, ctx context.Context, store *testStore, engine *Engine, namespace *Namespace, kind string) {
	t.Helper()

	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	namespaceState.Kind = kind
	require.NoError(t, store.SaveNamespace(ctx, namespaceState))
}

func setTestNamespaceHead(t *testing.T, ctx context.Context, store *testStore, engine *Engine, namespace *Namespace, head uint64) NamespaceState {
	t.Helper()

	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	namespaceState.NamespaceHead = head
	namespaceState.UpdatedAt = time.Now().UTC()
	require.NoError(t, store.SaveNamespace(ctx, namespaceState))
	return namespaceState
}

func newTestRawClient(t *testing.T, server *httptest.Server) *raw.Client {
	t.Helper()

	client, err := raw.New(server.URL, server.Client())
	require.NoError(t, err)
	return client
}

func encryptedTestItemResponse(t *testing.T, namespaceState NamespaceState, itemID string, version uint64, plaintext []byte) protocol.GetItemResponse {
	t.Helper()

	nonce, aad, ciphertext, err := protocol.EncryptItem(namespaceState.NamespaceID, itemID, version, namespaceState.DEK, plaintext)
	require.NoError(t, err)
	return protocol.GetItemResponse{
		NamespaceID: namespaceState.NamespaceID,
		ItemID:      itemID,
		Version:     version,
		Nonce:       protocol.EncodeBase64(nonce),
		AAD:         protocol.EncodeBase64(aad),
		Ciphertext:  protocol.EncodeBase64(ciphertext),
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(value))
}

func saveTestItem(t *testing.T, ctx context.Context, store *testStore, engine *Engine, namespace *Namespace, collection, key string, item ItemState) ItemState {
	t.Helper()

	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	itemID, err := protocol.ItemID(namespaceState.DEK, composeLogicalKey(collection, key))
	require.NoError(t, err)
	item.KeyID = engine.keyID
	item.NamespaceID = namespace.ID()
	item.Collection = collection
	item.Key = key
	item.ItemID = itemID
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Unix(100, 0).UTC()
	}
	require.NoError(t, store.SaveItem(ctx, item))
	saved, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), collection, key)
	require.NoError(t, err)
	return saved
}

func saveDirtyTestValue(
	t *testing.T,
	ctx context.Context,
	backend *MemoryValueBackend[string],
	store *testStore,
	engine *Engine,
	namespace *Namespace,
	collection string,
	key string,
	value string,
	item ItemState,
) ItemState {
	t.Helper()

	require.NoError(t, backend.Set(ctx, key, value))
	item.Dirty = true
	return saveTestItem(t, ctx, store, engine, namespace, collection, key, item)
}

func assertSameStoredItem(t *testing.T, ctx context.Context, store *testStore, engine *Engine, namespace *Namespace, collection, key string, want ItemState) {
	t.Helper()

	got, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), collection, key)
	require.NoError(t, err, key)
	require.Equal(t, want.ItemID, got.ItemID, key)
	require.Equal(t, want.Version, got.Version, key)
	require.Equal(t, want.BaseVersion, got.BaseVersion, key)
	require.Equal(t, want.Dirty, got.Dirty, key)
	require.Equal(t, want.Conflict, got.Conflict, key)
	require.Equal(t, want.ConflictRemoteVersion, got.ConflictRemoteVersion, key)
	require.Equal(t, want.BaseValue, got.BaseValue, key)
	require.Equal(t, want.ConflictRemoteValue, got.ConflictRemoteValue, key)
	require.True(t, got.UpdatedAt.Equal(want.UpdatedAt), key)
}

func drainEvents(engine *Engine) []Event {
	var events []Event
	for {
		select {
		case event := <-engine.Events():
			events = append(events, event)
		default:
			return events
		}
	}
}

func hasEventType(events []Event, eventType EventType) bool {
	return slices.ContainsFunc(events, func(event Event) bool {
		return event.Type == eventType
	})
}

type testStore struct {
	mu         sync.RWMutex
	identities map[string]IdentityState
	namespaces map[string]NamespaceState
	itemsByID  map[string]ItemState
	itemsByKey map[string]string
}

func newTestStore() *testStore {
	return &testStore{
		identities: make(map[string]IdentityState),
		namespaces: make(map[string]NamespaceState),
		itemsByID:  make(map[string]ItemState),
		itemsByKey: make(map[string]string),
	}
}

func (s *testStore) Close() error {
	return nil
}

func (s *testStore) LoadIdentity(_ context.Context, keyID string) (IdentityState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.identities[keyID]
	if !ok {
		return IdentityState{}, ErrNotFound
	}
	return state, nil
}

func (s *testStore) SaveIdentity(_ context.Context, state IdentityState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[state.KeyID] = state
	return nil
}

func (s *testStore) GetNamespace(_ context.Context, keyID, namespaceID string) (NamespaceState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.namespaces[namespaceStoreKey(keyID, namespaceID)]
	if !ok {
		return NamespaceState{}, ErrNotFound
	}
	return cloneNamespaceState(state), nil
}

func (s *testStore) ListNamespaces(_ context.Context, keyID string) ([]NamespaceState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []NamespaceState
	for _, state := range s.namespaces {
		if state.KeyID == keyID {
			out = append(out, cloneNamespaceState(state))
		}
	}
	return out, nil
}

func (s *testStore) SaveNamespace(_ context.Context, state NamespaceState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.namespaces[namespaceStoreKey(state.KeyID, state.NamespaceID)] = cloneNamespaceState(state)
	return nil
}

func (s *testStore) ForgetIdentitySecrets(_ context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state, ok := s.identities[keyID]; ok {
		state.AccessToken = ""
		state.TokenExpiry = time.Time{}
		s.identities[keyID] = state
	}
	for namespaceKey, state := range s.namespaces {
		if state.KeyID == keyID {
			state.DEK = nil
			s.namespaces[namespaceKey] = state
		}
	}
	return nil
}

func (s *testStore) ResetSyncState(_ context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state, ok := s.identities[keyID]; ok {
		state.DefaultNamespaceID = ""
		s.identities[keyID] = state
	}
	for namespaceKey, state := range s.namespaces {
		if state.KeyID == keyID {
			delete(s.namespaces, namespaceKey)
		}
	}
	for itemKey, state := range s.itemsByID {
		if state.KeyID == keyID {
			delete(s.itemsByID, itemKey)
		}
	}
	for logicalKey, itemKey := range s.itemsByKey {
		if _, ok := s.itemsByID[itemKey]; !ok {
			delete(s.itemsByKey, logicalKey)
		}
	}
	return nil
}

func (s *testStore) GetItemByID(_ context.Context, keyID, namespaceID, itemID string) (ItemState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.itemsByID[itemStoreKey(keyID, namespaceID, itemID)]
	if !ok {
		return ItemState{}, ErrNotFound
	}
	return cloneItemState(item), nil
}

func (s *testStore) GetItemByLogicalKey(_ context.Context, keyID, namespaceID, collection, key string) (ItemState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idKey, ok := s.itemsByKey[itemLogicalStoreKey(keyID, namespaceID, collection, key)]
	if !ok {
		return ItemState{}, ErrNotFound
	}
	item, ok := s.itemsByID[idKey]
	if !ok {
		return ItemState{}, ErrNotFound
	}
	return cloneItemState(item), nil
}

func (s *testStore) ListNamespaceItems(_ context.Context, keyID, namespaceID string) ([]ItemState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ItemState
	for _, item := range s.itemsByID {
		if item.KeyID == keyID && item.NamespaceID == namespaceID {
			out = append(out, cloneItemState(item))
		}
	}
	return out, nil
}

func (s *testStore) ListDirtyItems(_ context.Context, keyID string) ([]ItemState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ItemState
	for _, item := range s.itemsByID {
		if item.KeyID == keyID && item.Dirty {
			out = append(out, cloneItemState(item))
		}
	}
	return out, nil
}

func (s *testStore) SaveItem(_ context.Context, state ItemState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item := cloneItemState(state)
	idKey := itemStoreKey(item.KeyID, item.NamespaceID, item.ItemID)
	s.itemsByID[idKey] = item
	s.itemsByKey[itemLogicalStoreKey(item.KeyID, item.NamespaceID, item.Collection, item.Key)] = idKey
	return nil
}

func namespaceStoreKey(keyID, namespaceID string) string {
	return joinKeyParts(keyID, namespaceID)
}

func itemStoreKey(keyID, namespaceID, itemID string) string {
	return joinKeyParts(keyID, namespaceID, itemID)
}

func itemLogicalStoreKey(keyID, namespaceID, collection, key string) string {
	return joinKeyParts(keyID, namespaceID, collection, key)
}

func cloneNamespaceState(state NamespaceState) NamespaceState {
	state.DEK = bytes.Clone(state.DEK)
	return state
}

func cloneItemState(state ItemState) ItemState {
	state.BaseValue = bytes.Clone(state.BaseValue)
	state.ConflictRemoteValue = bytes.Clone(state.ConflictRemoteValue)
	return state
}
