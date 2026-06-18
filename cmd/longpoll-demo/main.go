// SPDX-License-Identifier: Apache-2.0

// Command longpoll-demo shows namespace long polling delivering remote writes
// promptly despite a slow fallback poll interval.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/bitboxsync"
	"github.com/BitBoxSwiss/bitboxsync-client-go/raw"
	sqlitestore "github.com/BitBoxSwiss/bitboxsync-client-go/storage/sqlite"
)

const (
	collectionName = "longpoll"
	writeDelay     = 3 * time.Second
	pollInterval   = 5 * time.Minute
)

var itemKeys = []string{
	"stream:item:1",
	"stream:item:2",
	"stream:item:3",
	"stream:item:4",
	"stream:item:5",
}

type receivedItem struct {
	key   string
	value string
}

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

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	baseURL := env("BITBOXSYNC_BASE_URL", "http://localhost:8090")
	publicOrigin := env("BITBOXSYNC_PUBLIC_ORIGIN", "https://sync.example")
	client, err := raw.New(baseURL, nil)
	if err != nil {
		log.Fatalf("create raw client: %v", err)
	}

	runID := time.Now().UTC().Format("20060102T150405.000000000")
	aliceStorePath := demoStorePath("alice", runID)
	bobStorePath := demoStorePath("bob", runID)
	defer cleanupStoreFiles(aliceStorePath)
	defer cleanupStoreFiles(bobStorePath)

	aliceStore, err := sqlitestore.Open(aliceStorePath)
	if err != nil {
		log.Fatalf("open alice sqlite store: %v", err)
	}
	bobStore, err := sqlitestore.Open(bobStorePath)
	if err != nil {
		log.Fatalf("open bob sqlite store: %v", err)
	}

	aliceIdentity, err := raw.NewDummyKeystore("longpoll-demo-alice-" + runID)
	if err != nil {
		log.Fatalf("create alice identity: %v", err)
	}
	bobIdentity, err := raw.NewDummyKeystore("longpoll-demo-bob-" + runID)
	if err != nil {
		log.Fatalf("create bob identity: %v", err)
	}

	alice, err := bitboxsync.Open(ctx, bitboxsync.Config{
		Client:       client,
		Identity:     aliceIdentity,
		Store:        aliceStore,
		PollInterval: pollInterval,
		EventBuffer:  128,
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
		PollInterval: pollInterval,
		EventBuffer:  128,
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
	log.Printf("default namespaces ready: alice=%s bob=%s", aliceDefault.ID(), bobDefault.ID())

	shared, err := alice.CreateSharedNamespace(ctx)
	if err != nil {
		log.Fatalf("create shared namespace: %v", err)
	}
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
	bobShared, err := bob.JoinNamespace(ctx, shared.ID())
	if err != nil {
		log.Fatalf("bob join shared namespace: %v", err)
	}
	log.Printf("shared namespace ready: %s", shared.ID())

	aliceBackend := bitboxsync.NewMemoryValueBackend[string](nil)
	_, err = bitboxsync.OpenCollection(shared, collectionName, bitboxsync.CollectionConfig[string]{
		Codec:   bitboxsync.StringCodec(),
		Merge:   bitboxsync.PreferLocal[string](),
		Backend: aliceBackend,
	})
	if err != nil {
		log.Fatalf("open alice collection: %v", err)
	}
	bobBackend := newScopedMemoryBackend[string](itemKeys...)
	_, err = bitboxsync.OpenCollection(bobShared, collectionName, bitboxsync.CollectionConfig[string]{
		Codec:   bitboxsync.StringCodec(),
		Merge:   bitboxsync.PreferLocal[string](),
		Backend: bobBackend,
	})
	if err != nil {
		log.Fatalf("open bob collection: %v", err)
	}

	errs := make(chan error, 4)
	aliceRunCtx, aliceCancel := context.WithCancel(ctx)
	defer aliceCancel()
	aliceDone := runEngine(aliceRunCtx, "alice", alice, errs)
	bobRunCtx, bobCancel := context.WithCancel(ctx)
	defer bobCancel()
	bobDone := runEngine(bobRunCtx, "bob", bob, errs)

	waitCtx, waitCancel := context.WithTimeout(ctx, 15*time.Second)
	if err := waitForInitialSync(waitCtx, alice, "alice"); err != nil {
		waitCancel()
		log.Fatalf("wait for alice initial sync: %v", err)
	}
	if err := waitForInitialSync(waitCtx, bob, "bob"); err != nil {
		waitCancel()
		log.Fatalf("wait for bob initial sync: %v", err)
	}
	waitCancel()

	log.Printf("both engines are running; fallback poll interval is %s", pollInterval)
	log.Printf("alice will write %d items with %s between writes; bob should receive each promptly via long poll", len(itemKeys), writeDelay)
	time.Sleep(500 * time.Millisecond)

	var sentTimes sync.Map
	received := make(chan receivedItem, len(itemKeys))
	go monitorBob(ctx, bob, bobBackend, &sentTimes, received, errs)
	go writeAliceItems(ctx, alice, aliceBackend, &sentTimes, errs)

	seen := make(map[string]struct{}, len(itemKeys))
	timeout := time.NewTimer(time.Duration(len(itemKeys))*writeDelay + 30*time.Second)
	defer timeout.Stop()
	for len(seen) < len(itemKeys) {
		select {
		case item := <-received:
			if _, ok := seen[item.key]; ok {
				continue
			}
			seen[item.key] = struct{}{}
		case err := <-errs:
			log.Fatalf("demo error: %v", err)
		case <-timeout.C:
			log.Fatalf("timed out after receiving %d/%d items", len(seen), len(itemKeys))
		}
	}

	log.Printf("bob received all %d writes without waiting for the %s fallback poll", len(itemKeys), pollInterval)
	aliceCancel()
	bobCancel()
	waitDone("alice", aliceDone)
	waitDone("bob", bobDone)
}

func runEngine(ctx context.Context, name string, engine *bitboxsync.Engine, errs chan<- error) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := engine.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, bitboxsync.ErrClosed) {
			sendErr(errs, fmt.Errorf("%s run: %w", name, err))
		}
	}()
	return done
}

func waitForInitialSync(ctx context.Context, engine *bitboxsync.Engine, name string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-engine.Events():
			if !ok {
				return bitboxsync.ErrClosed
			}
			switch event.Type {
			case bitboxsync.EventSyncFinished:
				log.Printf("%s initial sync finished", name)
				return nil
			case bitboxsync.EventSyncFailed:
				return fmt.Errorf("%s initial sync failed: %w", name, event.Err)
			}
		}
	}
}

func writeAliceItems(ctx context.Context, engine *bitboxsync.Engine, backend *bitboxsync.MemoryValueBackend[string], sentTimes *sync.Map, errs chan<- error) {
	for i, key := range itemKeys {
		if i > 0 {
			if !sleepOrDone(ctx, writeDelay) {
				return
			}
		}
		value := fmt.Sprintf("alice value %d at %s", i+1, time.Now().Format(time.RFC3339Nano))
		sentAt := time.Now()
		sentTimes.Store(key, sentAt)
		log.Printf("alice wrote %s=%q; SyncNow uploads it so bob's long poll can wake", key, value)
		if err := backend.Set(ctx, key, value); err != nil {
			sendErr(errs, fmt.Errorf("alice write %s: %w", key, err))
			return
		}
		if err := engine.SyncNow(ctx); err != nil {
			sendErr(errs, fmt.Errorf("alice sync %s: %w", key, err))
			return
		}
	}
}

func monitorBob(ctx context.Context, engine *bitboxsync.Engine, backend bitboxsync.ValueBackend[string], sentTimes *sync.Map, received chan<- receivedItem, errs chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-engine.Events():
			if !ok {
				return
			}
			switch event.Type {
			case bitboxsync.EventNamespaceWatchFailed:
				log.Printf("bob namespace watch warning: %v", event.Err)
			case bitboxsync.EventSyncFailed:
				sendErr(errs, fmt.Errorf("bob sync failed: %w", event.Err))
				return
			case bitboxsync.EventItemDownloaded:
				if event.Collection != collectionName {
					continue
				}
				value, err := backend.Get(ctx, event.Key)
				if err != nil {
					sendErr(errs, fmt.Errorf("bob read %s: %w", event.Key, err))
					return
				}
				elapsed := "unknown latency"
				if sentAt, ok := sentTimes.Load(event.Key); ok {
					elapsed = time.Since(sentAt.(time.Time)).Round(time.Millisecond).String()
				}
				log.Printf("bob received %s=%q after %s", event.Key, value, elapsed)
				received <- receivedItem{key: event.Key, value: value}
			}
		}
	}
}

func sendErr(errs chan<- error, err error) {
	select {
	case errs <- err:
	default:
	}
}

func sleepOrDone(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func waitDone(name string, done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Printf("%s Run did not stop within 5s", name)
	}
}

func demoStorePath(name, runID string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("bitboxsync-longpoll-%s-%s.sqlite", name, runID))
}

func cleanupStoreFiles(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + "-shm")
	_ = os.Remove(path + "-wal")
}

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
