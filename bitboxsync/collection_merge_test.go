// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/stretchr/testify/require"
)

func TestConcurrentCreateWithoutMergeBaseRecordsConflictForStrictCodec(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	// Regression test for concurrent creates. A new local item has no merge
	// base: Version, BaseVersion, and BaseValue are all zero. If another client
	// already created the same item remotely, the failed create path fetches the
	// remote value. The engine must pass nil as the merge base instead of asking
	// the collection codec to decode an absent value, because strict codecs may
	// reject empty payloads even though the concurrent-create conflict itself is
	// valid and recoverable.
	backend := NewMemoryValueBackend[string](nil)
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   strictNonEmptyStringCodec(),
		Merge:   NoMerge[string](),
		Backend: backend,
	})
	require.NoError(t, err)
	item := saveDirtyTestValue(t, ctx, backend, store, engine, namespace, "notes", "same-key", "local create", ItemState{})
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	remoteResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 1, []byte("remote create"))

	var putCalls int
	var getCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/"+namespace.ID()+"/"+item.ItemID {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			putCalls++
			require.Empty(t, r.Header.Get("If-Match"))
			writePreconditionFailed(t, w)
		case http.MethodGet:
			getCalls++
			writeTestJSON(t, w, remoteResp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.flushDirtyItems(ctx))
	require.Equal(t, 1, putCalls)
	require.Equal(t, 1, getCalls)

	value, err := backend.Get(ctx, "same-key")
	require.NoError(t, err)
	require.Equal(t, "local create", value)

	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "same-key")
	require.NoError(t, err)
	require.True(t, stored.Dirty)
	require.True(t, stored.Conflict)
	require.Equal(t, uint64(1), stored.Version)
	require.Zero(t, stored.BaseVersion)
	require.Empty(t, stored.BaseValue)
	require.Equal(t, uint64(1), stored.ConflictRemoteVersion)
	require.Equal(t, "remote create", string(stored.ConflictRemoteValue))
}

func TestUnresolvedMergeDoesNotEncodePlaceholderValue(t *testing.T) {
	mergeBytes := makeMergeBytes(
		rejectEmptyEncodeStringCodec(),
		func(_ string, _ *string, _, _ string) (string, bool, error) {
			return "", false, nil
		},
	)

	merged, resolved, err := mergeBytes("same-key", nil, []byte("local"), []byte("remote"))
	require.NoError(t, err)
	require.False(t, resolved)
	require.Nil(t, merged)
}

func TestConcurrentCreateWithoutMergeBaseCanResolve(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend[string](nil)
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferLocal[string](),
		Backend: backend,
	})
	require.NoError(t, err)
	item := saveDirtyTestValue(t, ctx, backend, store, engine, namespace, "notes", "same-key", "local create", ItemState{})
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	remoteResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 1, []byte("remote create"))

	var putCalls int
	var getCalls int
	var retryIfMatch string
	var retryPlaintext []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/"+namespace.ID()+"/"+item.ItemID {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			putCalls++
			switch putCalls {
			case 1:
				require.Empty(t, r.Header.Get("If-Match"))
				writePreconditionFailed(t, w)
			case 2:
				retryIfMatch = r.Header.Get("If-Match")
				retryPlaintext = decryptTestPutItemRequest(t, namespaceState, item.ItemID, 2, r)
				writeTestJSON(t, w, protocol.PutItemResponse{
					NamespaceID: namespace.ID(),
					ItemID:      item.ItemID,
					Version:     2,
				})
			default:
				require.Failf(t, "unexpected extra PUT", "%d", putCalls)
			}
		case http.MethodGet:
			getCalls++
			require.Equal(t, 1, getCalls)
			writeTestJSON(t, w, remoteResp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.flushDirtyItems(ctx))
	require.Equal(t, 2, putCalls)
	require.Equal(t, 1, getCalls)
	require.Equal(t, protocol.QuoteETag(1), retryIfMatch)
	require.Equal(t, "local create", string(retryPlaintext))

	value, err := backend.Get(ctx, "same-key")
	require.NoError(t, err)
	require.Equal(t, "local create", value)

	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "same-key")
	require.NoError(t, err)
	require.False(t, stored.Dirty)
	require.False(t, stored.Conflict)
	require.Equal(t, uint64(2), stored.Version)
	require.Equal(t, uint64(2), stored.BaseVersion)
	require.Equal(t, "local create", string(stored.BaseValue))
}

// TestResolvedUploadConflictRetriesMergedValueInSameFlush verifies that an
// upload-time version conflict which auto-merges successfully is not left dirty
// until a later poll. The first upload races with a newer remote version, the
// engine fetches that version, PreferLocal resolves the merge, and the same
// flush must retry exactly once with the fetched remote version as If-Match.
func TestResolvedUploadConflictRetriesMergedValueInSameFlush(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend(map[string]string{
		"same-key": "local edit",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferLocal[string](),
		Backend: backend,
	})
	require.NoError(t, err)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "same-key", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("base value"),
		Dirty:       true,
	})
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	remoteResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 2, []byte("remote edit"))

	var putCalls int
	var getCalls int
	var retryIfMatch string
	var retryPlaintext []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/"+namespace.ID()+"/"+item.ItemID {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			putCalls++
			switch putCalls {
			case 1:
				require.Equal(t, protocol.QuoteETag(1), r.Header.Get("If-Match"))
				writePreconditionFailed(t, w)
			case 2:
				retryIfMatch = r.Header.Get("If-Match")
				retryPlaintext = decryptTestPutItemRequest(t, namespaceState, item.ItemID, 3, r)
				writeTestJSON(t, w, protocol.PutItemResponse{
					NamespaceID: namespace.ID(),
					ItemID:      item.ItemID,
					Version:     3,
				})
			default:
				require.Failf(t, "unexpected extra PUT", "%d", putCalls)
			}
		case http.MethodGet:
			getCalls++
			require.Equal(t, 1, getCalls)
			writeTestJSON(t, w, remoteResp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	// This regression covers the upload-time conflict path. The first PUT races
	// with remote version 2 and gets a precondition failure. The engine fetches
	// version 2, auto-merges with PreferLocal, and must immediately retry the
	// merged value in the same flush. Without the retry, SyncNow/flushDirtyItems
	// would return with a resolved value still dirty until a future poll.
	require.NoError(t, engine.flushDirtyItems(ctx))
	require.Equal(t, 2, putCalls)
	require.Equal(t, 1, getCalls)
	require.Equal(t, protocol.QuoteETag(2), retryIfMatch)
	require.Equal(t, "local edit", string(retryPlaintext))

	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "same-key")
	require.NoError(t, err)
	require.False(t, stored.Dirty)
	require.False(t, stored.Conflict)
	require.Equal(t, uint64(3), stored.Version)
	require.Equal(t, uint64(3), stored.BaseVersion)
	require.Equal(t, "local edit", string(stored.BaseValue))
}

// TestUploadConflictAcceptingRemoteDoesNotRetry verifies that a resolved merge
// which chooses the already-fetched remote value is accepted as clean instead
// of being written back as a redundant new remote version.
func TestUploadConflictAcceptingRemoteDoesNotRetry(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend(map[string]string{
		"same-key": "local edit",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferRemote[string](),
		Backend: backend,
	})
	require.NoError(t, err)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "same-key", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("base value"),
		Dirty:       true,
	})
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	remoteResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 2, []byte("remote edit"))

	var putCalls int
	var getCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/"+namespace.ID()+"/"+item.ItemID {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			putCalls++
			require.LessOrEqual(t, putCalls, 1)
			require.Equal(t, protocol.QuoteETag(1), r.Header.Get("If-Match"))
			writePreconditionFailed(t, w)
		case http.MethodGet:
			getCalls++
			require.Equal(t, 1, getCalls)
			writeTestJSON(t, w, remoteResp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.flushDirtyItems(ctx))
	require.Equal(t, 1, putCalls)
	require.Equal(t, 1, getCalls)
	value, err := backend.Get(ctx, "same-key")
	require.NoError(t, err)
	require.Equal(t, "remote edit", value)
	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "same-key")
	require.NoError(t, err)
	require.False(t, stored.Dirty)
	require.False(t, stored.Conflict)
	require.Equal(t, uint64(2), stored.Version)
	require.Equal(t, uint64(2), stored.BaseVersion)
	require.Equal(t, "remote edit", string(stored.BaseValue))
}

// TestResolvedUploadConflictRefreshesWhenRetryAlsoConflicts verifies the retry
// bound. If the immediate retry races another writer too, the engine fetches
// that newer remote state so the item is left dirty against the latest known
// base, but it does not issue a third upload attempt in the same flush.
func TestResolvedUploadConflictRefreshesWhenRetryAlsoConflicts(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend(map[string]string{
		"same-key": "local edit",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferLocal[string](),
		Backend: backend,
	})
	require.NoError(t, err)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "same-key", ItemState{
		Version:     1,
		BaseVersion: 1,
		BaseValue:   []byte("base value"),
		Dirty:       true,
	})
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	firstRemoteResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 2, []byte("remote edit"))
	secondRemoteResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 3, []byte("newer remote edit"))

	var putCalls int
	var getCalls int
	var retryPlaintext []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/"+namespace.ID()+"/"+item.ItemID {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			putCalls++
			switch putCalls {
			case 1:
				require.Equal(t, protocol.QuoteETag(1), r.Header.Get("If-Match"))
				writePreconditionFailed(t, w)
			case 2:
				require.Equal(t, protocol.QuoteETag(2), r.Header.Get("If-Match"))
				retryPlaintext = decryptTestPutItemRequest(t, namespaceState, item.ItemID, 3, r)
				writePreconditionFailed(t, w)
			default:
				require.Fail(t, "unexpected third PUT")
			}
		case http.MethodGet:
			getCalls++
			switch getCalls {
			case 1:
				writeTestJSON(t, w, firstRemoteResp)
			case 2:
				writeTestJSON(t, w, secondRemoteResp)
			default:
				require.Failf(t, "unexpected GET", "%d", getCalls)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.flushDirtyItems(ctx))
	require.Equal(t, 2, putCalls)
	require.Equal(t, 2, getCalls)
	require.Equal(t, "local edit", string(retryPlaintext))

	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "same-key")
	require.NoError(t, err)
	require.True(t, stored.Dirty)
	require.False(t, stored.Conflict)
	require.Equal(t, uint64(3), stored.Version)
	require.Equal(t, uint64(3), stored.BaseVersion)
	require.Equal(t, "newer remote edit", string(stored.BaseValue))
	value, err := backend.Get(ctx, "same-key")
	require.NoError(t, err)
	require.Equal(t, "local edit", value)
}

func TestUploadConflictRejectsFetchedRollbackVersion(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	backend := NewMemoryValueBackend(map[string]string{
		"same-key": "local edit",
	})
	_, err := OpenCollection(namespace, "notes", CollectionConfig[string]{
		Codec:   StringCodec(),
		Merge:   PreferLocal[string](),
		Backend: backend,
	})
	require.NoError(t, err)
	item := saveTestItem(t, ctx, store, engine, namespace, "notes", "same-key", ItemState{
		Version:     2,
		BaseVersion: 2,
		BaseValue:   []byte("base value"),
		Dirty:       true,
	})
	namespaceState, err := store.GetNamespace(ctx, engine.keyID, namespace.ID())
	require.NoError(t, err)
	rollbackRemoteResp := encryptedTestItemResponse(t, namespaceState, item.ItemID, 1, []byte("old remote"))

	var putCalls int
	var getCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/"+namespace.ID()+"/"+item.ItemID {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			putCalls++
			require.Equal(t, 1, putCalls)
			require.Equal(t, protocol.QuoteETag(2), r.Header.Get("If-Match"))
			writePreconditionFailed(t, w)
		case http.MethodGet:
			getCalls++
			require.Equal(t, 1, getCalls)
			writeTestJSON(t, w, rollbackRemoteResp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	err = engine.flushDirtyItems(ctx)
	require.ErrorIs(t, err, ErrRollback)
	require.Equal(t, 1, putCalls)
	require.Equal(t, 1, getCalls)

	stored, err := store.GetItemByLogicalKey(ctx, engine.keyID, namespace.ID(), "notes", "same-key")
	require.NoError(t, err)
	require.True(t, stored.Dirty)
	require.False(t, stored.Conflict)
	require.Equal(t, uint64(2), stored.Version)
	require.Equal(t, uint64(2), stored.BaseVersion)
	require.Equal(t, "base value", string(stored.BaseValue))
}

func strictNonEmptyStringCodec() Codec[string] {
	return codecFunc[string]{
		encode: func(value string) ([]byte, error) {
			return []byte(value), nil
		},
		decode: func(payload []byte) (string, error) {
			if len(payload) == 0 {
				return "", errors.New("empty payload has no string value")
			}
			return string(payload), nil
		},
	}
}

func rejectEmptyEncodeStringCodec() Codec[string] {
	return codecFunc[string]{
		encode: func(value string) ([]byte, error) {
			if value == "" {
				return nil, errors.New("empty value cannot be encoded")
			}
			return []byte(value), nil
		},
		decode: func(payload []byte) (string, error) {
			return string(payload), nil
		},
	}
}

func writePreconditionFailed(t *testing.T, w http.ResponseWriter) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPreconditionFailed)
	_, err := w.Write([]byte(`{"error":"item already exists"}`))
	require.NoError(t, err)
}

func decryptTestPutItemRequest(t *testing.T, namespaceState NamespaceState, itemID string, version uint64, r *http.Request) []byte {
	t.Helper()

	var req protocol.PutItemRequest
	require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
	nonce, err := protocol.DecodeBase64("nonce", req.Nonce)
	require.NoError(t, err)
	aad, err := protocol.DecodeBase64("aad", req.AAD)
	require.NoError(t, err)
	require.NoError(t, protocol.VerifyAAD(namespaceState.NamespaceID, itemID, version, aad))
	ciphertext, err := protocol.DecodeBase64("ciphertext", req.Ciphertext)
	require.NoError(t, err)
	plaintext, err := protocol.DecryptItem(namespaceState.DEK, nonce, aad, ciphertext)
	require.NoError(t, err)
	return plaintext
}
