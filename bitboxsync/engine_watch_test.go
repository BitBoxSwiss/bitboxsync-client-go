// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"bitboxsync-client-go/protocol"
	"github.com/stretchr/testify/require"
)

func TestWatchNamespacesOnceSkipsAlreadyObservedSelfNotification(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestNamespaceHead(t, ctx, store, engine, namespace, 1)

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	var watchCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/watch" {
			http.NotFound(w, r)
			return
		}
		watchCalls.Add(1)
		var req protocol.WatchNamespacesRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, uint64(1), req.KnownHeads[namespace.ID()])
		writeTestJSON(t, w, protocol.WatchNamespacesResponse{
			Namespaces: []protocol.NamespaceSummary{{
				NamespaceID:   namespace.ID(),
				Kind:          protocol.NamespaceKindDefault,
				NamespaceHead: 1,
			}},
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	// A local upload can advance the local namespace head while an older long
	// poll is still outstanding. When that long poll wakes with a head the client
	// already observed, watch should reopen without asking Run for a redundant
	// sync. This test intentionally does not run Run; a sync request would block
	// until this context expires.
	watchCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	timedOut, err := engine.watchNamespacesOnce(watchCtx)
	require.NoError(t, err)
	require.False(t, timedOut)
	require.Equal(t, int64(1), watchCalls.Load())
}

func TestNamespaceWatchNeedsSyncRejectsRollbackHead(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestNamespaceHead(t, ctx, store, engine, namespace, 2)

	needsSync, err := engine.namespaceWatchNeedsSync(ctx, []protocol.NamespaceSummary{{
		NamespaceID:   namespace.ID(),
		Kind:          protocol.NamespaceKindDefault,
		NamespaceHead: 1,
	}})
	require.ErrorIs(t, err, ErrRollback)
	require.False(t, needsSync)
}

func TestNamespaceWatchLoginReconnectsAfterBackoff(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	engine.cfg.PollInterval = 200 * time.Millisecond
	engine.cfg.MaxPollInterval = time.Second

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	state.DefaultNamespaceID = namespace.ID()
	require.NoError(t, engine.saveIdentityState(ctx, state))

	firstWatchFailed := make(chan struct{})
	var firstWatchFailedClosed atomic.Bool
	var watchCalls atomic.Int64
	failWatch := atomic.Bool{}
	failWatch.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/mine":
			writeTestJSON(t, w, protocol.ListNamespacesResponse{})
		case "/v1/namespaces/watch":
			call := watchCalls.Add(1)
			if failWatch.Load() {
				if call == 1 && firstWatchFailedClosed.CompareAndSwap(false, true) {
					close(firstWatchFailed)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(`{"error":"boom"}`))
				require.NoError(t, err)
				return
			}
			writeTestJSON(t, w, protocol.WatchNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{},
				TimedOut:   true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go engine.runNamespaceWatch(watchCtx)

	select {
	case <-firstWatchFailed:
	case <-time.After(time.Second):
		require.Failf(t, "timed out waiting for first watch failure", "watch calls=%d", watchCalls.Load())
	}

	failWatch.Store(false)
	require.NoError(t, engine.Login(ctx))
	require.Eventually(t, func() bool {
		return watchCalls.Load() >= 2
	}, 120*time.Millisecond, 5*time.Millisecond, "namespace watch did not reconnect after login")
}

func TestRunSkipsQueuedWatchSyncForAlreadyObservedHeads(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	engine.cfg.DisableNamespaceWatch = true
	engine.cfg.PollInterval = time.Hour
	setTestNamespaceHead(t, ctx, store, engine, namespace, 1)

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	var listCalls atomic.Int64
	initialListed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/mine" {
			http.NotFound(w, r)
			return
		}
		if listCalls.Add(1) == 1 {
			close(initialListed)
		}
		writeTestJSON(t, w, protocol.ListNamespacesResponse{
			Namespaces: []protocol.NamespaceSummary{{
				NamespaceID:   namespace.ID(),
				Kind:          protocol.NamespaceKindDefault,
				NamespaceHead: 1,
			}},
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- engine.Run(runCtx)
	}()

	select {
	case <-initialListed:
	case <-time.After(time.Second):
		require.Fail(t, "timed out waiting for initial sync")
	}

	// This covers the race where a watch goroutine queued a sync request before
	// another sync pass finished saving the new local head. Run rechecks the
	// watch heads after receiving the request, so the completed local sync is
	// enough and no second sync pass should run.
	requestCtx, cancelRequest := context.WithTimeout(ctx, time.Second)
	defer cancelRequest()
	err := engine.requestRunSync(requestCtx, []protocol.NamespaceSummary{{
		NamespaceID:   namespace.ID(),
		Kind:          protocol.NamespaceKindDefault,
		NamespaceHead: 1,
	}})
	require.NoError(t, err)
	require.Equal(t, int64(1), listCalls.Load())

	cancel()
	if err := <-runDone; err != nil {
		require.ErrorIs(t, err, context.Canceled)
	}
}
