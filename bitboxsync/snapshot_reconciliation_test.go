// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bitboxsync-client-go/protocol"
	"github.com/stretchr/testify/require"
)

func TestReconcileLocalSnapshotsQueuesNewAndChangedValues(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend(map[string]string{
		"changed":  "edited memo",
		"clean":    "base memo",
		"conflict": "conflict memo",
		"dirty":    "already dirty memo",
		"new":      "new memo",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferLocal[string](),
		Backend: backend,
	})
	require.NoError(t, err)

	changedItem := saveTestItem(t, ctx, store, engine, namespace, "notes", "changed", ItemState{
		Version:     3,
		BaseVersion: 3,
		BaseValue:   []byte("base memo"),
	})
	cleanItem := saveTestItem(t, ctx, store, engine, namespace, "notes", "clean", ItemState{
		Version:     4,
		BaseVersion: 4,
		BaseValue:   []byte("base memo"),
	})
	conflictItem := saveTestItem(t, ctx, store, engine, namespace, "notes", "conflict", ItemState{
		Version:               5,
		Dirty:                 true,
		Conflict:              true,
		BaseValue:             []byte("base memo"),
		ConflictRemoteValue:   []byte("remote memo"),
		ConflictRemoteVersion: 6,
	})
	dirtyItem := saveTestItem(t, ctx, store, engine, namespace, "notes", "dirty", ItemState{
		Version:     7,
		BaseVersion: 7,
		BaseValue:   []byte("base memo"),
		Dirty:       true,
	})

	require.NoError(t, engine.reconcileLocalSnapshots(ctx))

	storedChanged, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "changed")
	require.NoError(t, err)
	require.True(t, storedChanged.Dirty)
	require.Equal(t, changedItem.Version, storedChanged.Version)
	require.Equal(t, changedItem.BaseValue, storedChanged.BaseValue)

	storedNew, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "new")
	require.NoError(t, err)
	require.True(t, storedNew.Dirty)
	require.Zero(t, storedNew.Version)

	assertSameStoredItem(t, ctx, store, engine, namespace, "notes", "clean", cleanItem)
	assertSameStoredItem(t, ctx, store, engine, namespace, "notes", "conflict", conflictItem)
	assertSameStoredItem(t, ctx, store, engine, namespace, "notes", "dirty", dirtyItem)

	events := drainEvents(engine)
	require.Len(t, events, 2)
	require.Equal(t, EventItemQueued, events[0].Type)
	require.Equal(t, "changed", events[0].Key)
	require.Equal(t, EventItemQueued, events[1].Type)
	require.Equal(t, "new", events[1].Key)
}

func TestSyncNowReconcilesSnapshotBeforeUpload(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	backend := NewMemoryValueBackend(map[string]string{
		"tx1": "edited memo",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferLocal[string](),
		Backend: backend,
	})
	require.NoError(t, err)

	namespaceState := setTestNamespaceHead(t, ctx, store, engine, namespace, 1)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "tx1", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("base memo"),
	})

	var putCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/mine":
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 1,
				}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+namespace.ID()+"/items":
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 1,
				Items: map[string]protocol.NamespaceItemVersion{
					item.ItemID: {Version: 1},
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/kv/"+namespace.ID()+"/"+item.ItemID:
			putCalls++
			require.Equal(t, protocol.QuoteETag(1), r.Header.Get("If-Match"))
			plaintext := decryptTestPutItemRequest(t, namespaceState, item.ItemID, 2, r)
			require.Equal(t, "edited memo", string(plaintext))
			writeTestJSON(t, w, protocol.PutItemResponse{
				NamespaceID: namespace.ID(),
				ItemID:      item.ItemID,
				Version:     2,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.SyncNow(ctx))
	require.Equal(t, 1, putCalls)

	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "tx1")
	require.NoError(t, err)
	require.False(t, stored.Dirty)
	require.False(t, stored.Conflict)
	require.Equal(t, uint64(2), stored.Version)
	require.Equal(t, uint64(2), stored.BaseVersion)
	require.Equal(t, []byte("edited memo"), stored.BaseValue)
}

func TestSyncNowDoesNotOverwriteLocalEditAfterSnapshot(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	backend := NewMemoryValueBackend(map[string]string{
		"tx1": "base memo",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferLocal[string](),
		Backend: backend,
	})
	require.NoError(t, err)

	namespaceState := setTestNamespaceHead(t, ctx, store, engine, namespace, 1)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "tx1", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("base memo"),
	})

	var localEditApplied bool
	var putCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/mine":
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 2,
				}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+namespace.ID()+"/items":
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 2,
				Items: map[string]protocol.NamespaceItemVersion{
					item.ItemID: {Version: 2},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/kv/"+namespace.ID()+"/"+item.ItemID:
			// The sync snapshot has already observed "base memo". This simulates
			// the app writing the same logical key before the downloaded remote
			// value is applied.
			require.NoError(t, backend.Set(ctx, "tx1", "local memo"))
			localEditApplied = true
			writeTestJSON(t, w, encryptedTestItemResponse(t, namespaceState, item.ItemID, 2, []byte("remote memo")))
		case r.Method == http.MethodPut && r.URL.Path == "/v1/kv/"+namespace.ID()+"/"+item.ItemID:
			putCalls++
			require.True(t, localEditApplied)
			require.Equal(t, protocol.QuoteETag(2), r.Header.Get("If-Match"))
			plaintext := decryptTestPutItemRequest(t, namespaceState, item.ItemID, 3, r)
			require.Equal(t, "local memo", string(plaintext))
			writeTestJSON(t, w, protocol.PutItemResponse{
				NamespaceID: namespace.ID(),
				ItemID:      item.ItemID,
				Version:     3,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.SyncNow(ctx))
	require.True(t, localEditApplied)
	require.Equal(t, 1, putCalls)

	value, err := backend.Get(ctx, "tx1")
	require.NoError(t, err)
	require.Equal(t, "local memo", value)
	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "tx1")
	require.NoError(t, err)
	require.False(t, stored.Dirty)
	require.False(t, stored.Conflict)
	require.Equal(t, uint64(3), stored.Version)
	require.Equal(t, uint64(3), stored.BaseVersion)
	require.Equal(t, []byte("local memo"), stored.BaseValue)
}

func TestSyncNowDoesNotOverwriteLocalEditBetweenRereadAndRemoteApply(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	backend := &raceOnSetIfCurrentBackend{
		MemoryValueBackend: NewMemoryValueBackend(map[string]string{
			"tx1": "base memo",
		}),
	}
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferLocal[string](),
		Backend: backend,
	})
	require.NoError(t, err)

	namespaceState := setTestNamespaceHead(t, ctx, store, engine, namespace, 1)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "tx1", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("base memo"),
	})
	backend.beforeSetIfCurrent = func() {
		require.NoError(t, backend.Set(ctx, "tx1", "local memo"))
	}

	var getItemCalls int
	var putCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/mine":
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 2,
				}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+namespace.ID()+"/items":
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 2,
				Items: map[string]protocol.NamespaceItemVersion{
					item.ItemID: {Version: 2},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/kv/"+namespace.ID()+"/"+item.ItemID:
			getItemCalls++
			writeTestJSON(t, w, encryptedTestItemResponse(t, namespaceState, item.ItemID, 2, []byte("remote memo")))
		case r.Method == http.MethodPut && r.URL.Path == "/v1/kv/"+namespace.ID()+"/"+item.ItemID:
			putCalls++
			switch putCalls {
			case 1:
				require.Equal(t, protocol.QuoteETag(1), r.Header.Get("If-Match"))
				writePreconditionFailed(t, w)
			case 2:
				require.Equal(t, protocol.QuoteETag(2), r.Header.Get("If-Match"))
				plaintext := decryptTestPutItemRequest(t, namespaceState, item.ItemID, 3, r)
				require.Equal(t, "local memo", string(plaintext))
				writeTestJSON(t, w, protocol.PutItemResponse{
					NamespaceID: namespace.ID(),
					ItemID:      item.ItemID,
					Version:     3,
				})
			default:
				require.Failf(t, "unexpected PUT", "call %d", putCalls)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.SyncNow(ctx))
	require.Equal(t, 2, getItemCalls)
	require.Equal(t, 2, putCalls)

	value, err := backend.Get(ctx, "tx1")
	require.NoError(t, err)
	require.Equal(t, "local memo", value)
	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "tx1")
	require.NoError(t, err)
	require.False(t, stored.Dirty)
	require.False(t, stored.Conflict)
	require.Equal(t, uint64(3), stored.Version)
	require.Equal(t, []byte("local memo"), stored.BaseValue)
}

type raceOnSetIfCurrentBackend struct {
	*MemoryValueBackend[string]
	beforeSetIfCurrent func()
}

func (b *raceOnSetIfCurrentBackend) SetIfCurrent(ctx context.Context, key string, current string, currentFound bool, value string) (bool, error) {
	if b.beforeSetIfCurrent != nil {
		beforeSetIfCurrent := b.beforeSetIfCurrent
		b.beforeSetIfCurrent = nil
		beforeSetIfCurrent()
	}
	return b.MemoryValueBackend.SetIfCurrent(ctx, key, current, currentFound, value)
}
