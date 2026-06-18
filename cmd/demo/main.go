// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"

	"bitboxsync-client-go/bitboxsync"
	"bitboxsync-client-go/raw"
	sqlitestore "bitboxsync-client-go/storage/sqlite"
)

type scopedMemoryBackend[T any] struct {
	*bitboxsync.MemoryValueBackend[T]
	keys []string
}

func newScopedMemoryBackend[T any](keys ...string) *scopedMemoryBackend[T] {
	return &scopedMemoryBackend[T]{
		MemoryValueBackend: bitboxsync.NewMemoryValueBackend[T](nil),
		keys:               slices.Clone(keys),
	}
}

func (b *scopedMemoryBackend[T]) Keys(context.Context) ([]string, error) {
	return slices.Clone(b.keys), nil
}

// main runs an end-to-end demonstration of the BitBoxSync client library
// against a reachable server.
func main() {
	baseURL := env("BITBOXSYNC_BASE_URL", "http://localhost:8090")
	publicOrigin := env("BITBOXSYNC_PUBLIC_ORIGIN", "https://sync.example")
	client, err := raw.New(baseURL, nil)
	if err != nil {
		log.Fatalf("create raw client: %v", err)
	}

	aliceStorePath := filepath.Join(os.TempDir(), "bitboxsync-demo-alice.sqlite")
	bobStorePath := filepath.Join(os.TempDir(), "bitboxsync-demo-bob.sqlite")
	_ = os.Remove(aliceStorePath)
	_ = os.Remove(bobStorePath)

	aliceStore, err := sqlitestore.Open(aliceStorePath)
	if err != nil {
		log.Fatalf("open alice sqlite store: %v", err)
	}
	bobStore, err := sqlitestore.Open(bobStorePath)
	if err != nil {
		log.Fatalf("open bob sqlite store: %v", err)
	}

	aliceIdentity, err := raw.NewDummyKeystore("demo-alice")
	if err != nil {
		log.Fatalf("create alice identity: %v", err)
	}
	bobIdentity, err := raw.NewDummyKeystore("demo-bob")
	if err != nil {
		log.Fatalf("create bob identity: %v", err)
	}

	ctx := context.Background()

	alice, err := bitboxsync.Open(ctx, bitboxsync.Config{
		Client:       client,
		Identity:     aliceIdentity,
		Store:        aliceStore,
		PollInterval: 5 * time.Minute,
	})
	if err != nil {
		closeOnExit("alice sqlite store", aliceStore)
		log.Fatalf("open alice sync engine: %v", err)
	}
	defer closeOnExit("alice sync engine", alice)

	bob, err := bitboxsync.Open(ctx, bitboxsync.Config{
		Client:       client,
		Identity:     bobIdentity,
		Store:        bobStore,
		PollInterval: 5 * time.Minute,
	})
	if err != nil {
		closeOnExit("bob sqlite store", bobStore)
		log.Fatalf("open bob sync engine: %v", err)
	}
	defer closeOnExit("bob sync engine", bob)

	aliceDefault, err := alice.DefaultNamespace(ctx)
	if err != nil {
		log.Fatalf("alice default namespace: %v", err)
	}
	bobDefault, err := bob.DefaultNamespace(ctx)
	if err != nil {
		log.Fatalf("bob default namespace: %v", err)
	}
	log.Printf("alice default namespace: %s", aliceDefault.ID())
	log.Printf("bob default namespace: %s", bobDefault.ID())

	aliceAppNotes := bitboxsync.NewMemoryValueBackend(map[string]string{
		"account:primary:label": "Alice savings",
	})
	_, err = bitboxsync.OpenCollection(aliceDefault, "notes", bitboxsync.CollectionConfig[string]{
		Codec:   bitboxsync.StringCodec(),
		Merge:   bitboxsync.PreferLocal[string](),
		Backend: aliceAppNotes,
	})
	if err != nil {
		log.Fatalf("open alice notes collection: %v", err)
	}
	recordValue, err := aliceAppNotes.Get(ctx, "account:primary:label")
	if err != nil {
		log.Fatalf("alice inspect preexisting app note: %v", err)
	}
	log.Printf("alice preexisting app note: %s", recordValue)

	if err := aliceAppNotes.Set(ctx, "account:secondary:label", "Alice checking"); err != nil {
		log.Fatalf("alice write app note: %v", err)
	}

	aliceRunCtx, aliceCancel := context.WithCancel(ctx)
	defer aliceCancel()
	go func() {
		_ = alice.Run(aliceRunCtx)
	}()

	bobRunCtx, bobCancel := context.WithCancel(ctx)
	defer bobCancel()
	go func() {
		_ = bob.Run(bobRunCtx)
	}()

	if err := alice.SyncNow(ctx); err != nil {
		log.Fatalf("alice sync default namespace: %v", err)
	}
	aliceValue, err := aliceAppNotes.Get(ctx, "account:primary:label")
	if err != nil {
		log.Fatalf("alice read default note: %v", err)
	}
	log.Printf("alice default item: %s", aliceValue)

	shared, err := alice.CreateSharedNamespace(ctx)
	if err != nil {
		log.Fatalf("create shared namespace: %v", err)
	}
	log.Printf("shared namespace created: %s", shared.ID())

	invite, err := shared.CreateInvite(ctx, bitboxsync.NamespaceInviteOptions{
		ServerOrigin: publicOrigin,
		TTL:          10 * time.Minute,
	})
	if err != nil {
		log.Fatalf("create namespace invite: %v", err)
	}
	inviteURI, err := bitboxsync.InviteURI(invite)
	if err != nil {
		log.Fatalf("encode namespace invite: %v", err)
	}
	scannedInvite, err := bitboxsync.ParseInviteURI(inviteURI)
	if err != nil {
		log.Fatalf("parse namespace invite: %v", err)
	}
	if _, err := bob.SubmitJoinRequest(ctx, scannedInvite, bitboxsync.NamespaceJoinRequestOptions{}); err != nil {
		log.Fatalf("submit bob join request: %v", err)
	}
	joinRequests, err := shared.JoinRequests(ctx)
	if err != nil {
		log.Fatalf("list join requests: %v", err)
	}
	if len(joinRequests) != 1 {
		log.Fatalf("expected 1 join request, got %d", len(joinRequests))
	}
	if err := shared.ApproveJoinRequest(ctx, invite, joinRequests[0]); err != nil {
		log.Fatalf("approve bob join request: %v", err)
	}
	log.Printf("alice approved bob for shared namespace")

	bobShared, err := bob.JoinNamespace(ctx, shared.ID())
	if err != nil {
		log.Fatalf("bob join shared namespace: %v", err)
	}
	sharedNotesBackend := bitboxsync.NewMemoryValueBackend[string](nil)
	_, err = bitboxsync.OpenCollection(shared, "drafts", bitboxsync.CollectionConfig[string]{
		Codec:   bitboxsync.StringCodec(),
		Merge:   bitboxsync.PreferLocal[string](),
		Backend: sharedNotesBackend,
	})
	if err != nil {
		log.Fatalf("open alice shared drafts collection: %v", err)
	}
	if err := sharedNotesBackend.Set(ctx, "shared:note", "Shared multisig draft metadata"); err != nil {
		log.Fatalf("write shared note: %v", err)
	}
	if err := alice.SyncNow(ctx); err != nil {
		log.Fatalf("sync shared namespace from alice: %v", err)
	}
	bobSharedBackend := newScopedMemoryBackend[string]("shared:note")
	_, err = bitboxsync.OpenCollection(bobShared, "drafts", bitboxsync.CollectionConfig[string]{
		Codec:   bitboxsync.StringCodec(),
		Merge:   bitboxsync.PreferLocal[string](),
		Backend: bobSharedBackend,
	})
	if err != nil {
		log.Fatalf("open bob shared drafts collection: %v", err)
	}
	if err := bob.SyncNow(ctx); err != nil {
		log.Fatalf("sync shared namespace from bob: %v", err)
	}
	sharedValue, err := bobSharedBackend.Get(ctx, "shared:note")
	if err != nil {
		log.Fatalf("bob read shared note: %v", err)
	}
	log.Printf("bob read shared note: %s", sharedValue)

	aliceConflictBackend := bitboxsync.NewMemoryValueBackend[string](nil)
	_, err = bitboxsync.OpenCollection(shared, "conflict-demo", bitboxsync.CollectionConfig[string]{
		Codec:   bitboxsync.StringCodec(),
		Merge:   bitboxsync.NoMerge[string](),
		Backend: aliceConflictBackend,
	})
	if err != nil {
		log.Fatalf("open alice conflict collection: %v", err)
	}
	bobConflictBackend := newScopedMemoryBackend[string]("same-key")
	bobConflictNotes, err := bitboxsync.OpenCollection(bobShared, "conflict-demo", bitboxsync.CollectionConfig[string]{
		Codec:   bitboxsync.StringCodec(),
		Merge:   bitboxsync.NoMerge[string](),
		Backend: bobConflictBackend,
	})
	if err != nil {
		log.Fatalf("open bob conflict collection: %v", err)
	}

	if err := aliceConflictBackend.Set(ctx, "same-key", "base value"); err != nil {
		log.Fatalf("seed conflict base value: %v", err)
	}
	if err := alice.SyncNow(ctx); err != nil {
		log.Fatalf("sync conflict base value from alice: %v", err)
	}
	if err := bob.SyncNow(ctx); err != nil {
		log.Fatalf("bob sync conflict base value: %v", err)
	}
	baseValue, err := bobConflictBackend.Get(ctx, "same-key")
	if err != nil {
		log.Fatalf("bob read conflict base value: %v", err)
	}
	log.Printf("bob fetched shared base value before conflict: %s", baseValue)

	if err := aliceConflictBackend.Set(ctx, "same-key", "alice local edit"); err != nil {
		log.Fatalf("alice write conflicting edit: %v", err)
	}
	if err := bobConflictBackend.Set(ctx, "same-key", "bob local edit"); err != nil {
		log.Fatalf("bob write conflicting edit: %v", err)
	}

	if err := alice.SyncNow(ctx); err != nil {
		log.Fatalf("alice sync conflicting edit: %v", err)
	}
	if err := bob.SyncNow(ctx); err != nil {
		log.Fatalf("bob sync conflicting edit: %v", err)
	}
	log.Printf("conflict detected on same key; resolving with an explicit value")

	if err := bobConflictNotes.ResolveConflictWithValue(ctx, "same-key", "alice and bob resolved this together"); err != nil {
		log.Fatalf("resolve conflict with merged value: %v", err)
	}
	if err := bob.SyncNow(ctx); err != nil {
		log.Fatalf("bob sync resolved conflict: %v", err)
	}
	if err := alice.SyncNow(ctx); err != nil {
		log.Fatalf("alice fetch resolved conflict: %v", err)
	}
	resolvedValue, err := aliceConflictBackend.Get(ctx, "same-key")
	if err != nil {
		log.Fatalf("alice read resolved conflict value: %v", err)
	}
	log.Printf("resolved shared value after conflict handling: %s", resolvedValue)

	namespaces, err := bob.ListNamespaces(ctx)
	if err != nil {
		log.Fatalf("list bob namespaces: %v", err)
	}
	log.Printf("bob sees %d namespaces", len(namespaces))

	if err := alice.SyncNow(ctx); err != nil {
		log.Fatalf("alice sync: %v", err)
	}
}

// env returns the configured environment variable or fallback when unset.
func env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func closeOnExit(name string, closer interface{ Close() error }) {
	if err := closer.Close(); err != nil {
		log.Printf("close %s: %v", name, err)
	}
}
