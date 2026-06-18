// SPDX-License-Identifier: Apache-2.0

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/bitboxsync"
	"github.com/stretchr/testify/require"
)

func TestOpenInMemoryReturnsIsolatedStores(t *testing.T) {
	ctx := context.Background()

	left, err := OpenInMemory()
	require.NoError(t, err)
	defer closeStore(t, left)

	right, err := OpenInMemory()
	require.NoError(t, err)
	defer closeStore(t, right)

	state := bitboxsync.IdentityState{
		KeyID:     "identity-a",
		Kind:      "keystore",
		UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, left.SaveIdentity(ctx, state))

	loaded, err := left.LoadIdentity(ctx, state.KeyID)
	require.NoError(t, err)
	require.Equal(t, state.KeyID, loaded.KeyID)

	_, err = right.LoadIdentity(ctx, state.KeyID)
	require.ErrorIs(t, err, bitboxsync.ErrNotFound)
}

func TestForgetIdentitySecretsKeepsSyncMetadata(t *testing.T) {
	ctx := context.Background()

	store, err := OpenInMemory()
	require.NoError(t, err)
	defer closeStore(t, store)

	keyID := "identity-a"
	otherKeyID := "identity-b"
	namespaceID := "namespace-a"
	require.NoError(t, store.SaveIdentity(ctx, bitboxsync.IdentityState{
		KeyID:              keyID,
		Kind:               "keystore",
		AccessToken:        "access-token",
		TokenExpiry:        time.Now().Add(time.Hour).UTC(),
		DefaultNamespaceID: namespaceID,
	}))
	require.NoError(t, store.SaveIdentity(ctx, bitboxsync.IdentityState{
		KeyID:              otherKeyID,
		Kind:               "keystore",
		AccessToken:        "other-access-token",
		TokenExpiry:        time.Now().Add(time.Hour).UTC(),
		DefaultNamespaceID: "namespace-b",
	}))
	require.NoError(t, store.SaveNamespace(ctx, bitboxsync.NamespaceState{
		KeyID:           keyID,
		NamespaceID:     namespaceID,
		Kind:            "default",
		NamespaceHead:   42,
		ActiveScopeHash: "scope",
		DEK:             []byte("namespace-dek"),
	}))
	require.NoError(t, store.SaveNamespace(ctx, bitboxsync.NamespaceState{
		KeyID:           otherKeyID,
		NamespaceID:     "namespace-b",
		Kind:            "default",
		NamespaceHead:   99,
		ActiveScopeHash: "other-scope",
		DEK:             []byte("other-namespace-dek"),
	}))
	require.NoError(t, store.SaveItem(ctx, bitboxsync.ItemState{
		KeyID:       keyID,
		NamespaceID: namespaceID,
		Collection:  "collection",
		Key:         "key",
		ItemID:      "item-id",
		Version:     7,
		BaseVersion: 7,
		BaseValue:   []byte("base-value"),
	}))

	require.NoError(t, store.ForgetIdentitySecrets(ctx, keyID))

	identity, err := store.LoadIdentity(ctx, keyID)
	require.NoError(t, err)
	require.Empty(t, identity.AccessToken)
	require.True(t, identity.TokenExpiry.IsZero())
	require.Equal(t, namespaceID, identity.DefaultNamespaceID)

	namespace, err := store.GetNamespace(ctx, keyID, namespaceID)
	require.NoError(t, err)
	require.Empty(t, namespace.DEK)
	require.Equal(t, uint64(42), namespace.NamespaceHead)
	require.Equal(t, "scope", namespace.ActiveScopeHash)

	item, err := store.GetItemByLogicalKey(ctx, keyID, namespaceID, "collection", "key")
	require.NoError(t, err)
	require.Equal(t, uint64(7), item.Version)
	require.Equal(t, []byte("base-value"), item.BaseValue)

	otherIdentity, err := store.LoadIdentity(ctx, otherKeyID)
	require.NoError(t, err)
	require.Equal(t, "other-access-token", otherIdentity.AccessToken)
	require.False(t, otherIdentity.TokenExpiry.IsZero())
	otherNamespace, err := store.GetNamespace(ctx, otherKeyID, "namespace-b")
	require.NoError(t, err)
	require.Equal(t, []byte("other-namespace-dek"), otherNamespace.DEK)
}

func closeStore(t *testing.T, store *Store) {
	t.Helper()
	require.NoError(t, store.Close())
}
