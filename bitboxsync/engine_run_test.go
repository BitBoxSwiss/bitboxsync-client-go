// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bitboxsync-client-go/protocol"
	"github.com/stretchr/testify/require"
)

func TestScheduleSyncCoalescesWakeups(t *testing.T) {
	ctx := context.Background()
	engine, _, _ := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	engine.ScheduleSync()
	engine.ScheduleSync()

	select {
	case <-engine.wakeSync:
	default:
		require.Fail(t, "ScheduleSync did not queue a wake-up")
	}
	select {
	case <-engine.wakeSync:
		require.Fail(t, "ScheduleSync queued more than one wake-up")
	default:
	}
}

func TestSyncNowEmitsFailureEvent(t *testing.T) {
	ctx := context.Background()
	engine, _, _ := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/mine" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(`{"error":"boom"}`))
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	err := engine.SyncNow(ctx)
	require.Error(t, err)

	events := drainEvents(engine)
	require.Len(t, events, 2)
	require.Equal(t, EventSyncStarted, events[0].Type)
	require.Equal(t, EventSyncFailed, events[1].Type)
	require.Error(t, events[1].Err)
}

func TestRunLoginResetsFailureBackoff(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	engine.cfg.DisableNamespaceWatch = true
	engine.cfg.PollInterval = 20 * time.Millisecond
	engine.cfg.MaxPollInterval = time.Second

	var listCalls atomic.Int64
	thirdFailure := make(chan struct{})
	var thirdFailureOnce sync.Once
	fail := atomic.Bool{}
	fail.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/mine" {
			http.NotFound(w, r)
			return
		}
		call := listCalls.Add(1)
		if fail.Load() {
			if call == 3 {
				thirdFailureOnce.Do(func() {
					close(thirdFailure)
				})
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(`{"error":"boom"}`))
			require.NoError(t, err)
			return
		}
		writeTestJSON(t, w, protocol.ListNamespacesResponse{})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	state.DefaultNamespaceID = namespace.ID()
	require.NoError(t, engine.saveIdentityState(ctx, state))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- engine.Run(runCtx)
	}()

	select {
	case <-thirdFailure:
	case <-time.After(time.Second):
		require.Failf(t, "timed out waiting for background failures", "list calls=%d", listCalls.Load())
	}

	fail.Store(false)
	require.NoError(t, engine.Login(ctx))
	loginCount := listCalls.Load()
	require.Eventually(t, func() bool {
		return listCalls.Load() >= loginCount+1
	}, 120*time.Millisecond, 5*time.Millisecond, "background sync did not reset to base interval after login")

	cancel()
	if err := <-runDone; err != nil {
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestRunSyncsAfterNamespaceWatchChange(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	engine.cfg.PollInterval = 100 * time.Millisecond

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	var namespaceHead atomic.Uint64
	var listCalls atomic.Int64
	var watchCalls atomic.Int64
	itemsSynced := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/mine":
			listCalls.Add(1)
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: namespaceHead.Load(),
				}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/watch":
			watchCalls.Add(1)
			var req protocol.WatchNamespacesRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			if req.KnownHeads[namespace.ID()] >= 1 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
				writeTestJSON(t, w, protocol.WatchNamespacesResponse{
					Namespaces: []protocol.NamespaceSummary{},
					TimedOut:   true,
				})
				return
			}
			namespaceHead.Store(1)
			writeTestJSON(t, w, protocol.WatchNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 1,
				}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+namespace.ID()+"/items":
			select {
			case <-itemsSynced:
			default:
				close(itemsSynced)
			}
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 1,
				Items:         map[string]protocol.NamespaceItemVersion{},
			})
		default:
			http.NotFound(w, r)
		}
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
	case <-itemsSynced:
	case <-time.After(time.Second):
		require.Failf(t, "timed out waiting for watch-triggered sync", "list calls=%d watch calls=%d head=%d", listCalls.Load(), watchCalls.Load(), namespaceHead.Load())
	}
	cancel()
	if err := <-runDone; err != nil {
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestRunNamespaceWatchWaitsForTriggeredSyncBeforeRewatch(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	engine.cfg.PollInterval = 100 * time.Millisecond

	state := engine.identityStateSnapshot()
	state.AccessToken = "token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	require.NoError(t, engine.saveIdentityState(ctx, state))

	var namespaceHead atomic.Uint64
	var listCalls atomic.Int64
	var watchCalls atomic.Int64
	itemsStarted := make(chan struct{})
	releaseItems := make(chan struct{})
	secondWatch := make(chan struct{})
	var itemsStartedOnce, releaseItemsOnce, secondWatchOnce sync.Once
	release := func() {
		releaseItemsOnce.Do(func() {
			close(releaseItems)
		})
	}
	defer release()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/mine":
			listCalls.Add(1)
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: namespaceHead.Load(),
				}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/watch":
			if watchCalls.Add(1) > 1 {
				secondWatchOnce.Do(func() {
					close(secondWatch)
				})
			}
			var req protocol.WatchNamespacesRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			if req.KnownHeads[namespace.ID()] >= 1 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
				writeTestJSON(t, w, protocol.WatchNamespacesResponse{
					Namespaces: []protocol.NamespaceSummary{},
					TimedOut:   true,
				})
				return
			}
			namespaceHead.Store(1)
			writeTestJSON(t, w, protocol.WatchNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 1,
				}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+namespace.ID()+"/items":
			itemsStartedOnce.Do(func() {
				close(itemsStarted)
			})
			select {
			case <-releaseItems:
			case <-r.Context().Done():
				return
			}
			writeTestJSON(t, w, protocol.GetNamespaceItemsResponse{
				NamespaceID:   namespace.ID(),
				NamespaceHead: 1,
				Items:         map[string]protocol.NamespaceItemVersion{},
			})
		default:
			http.NotFound(w, r)
		}
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
	case <-itemsStarted:
	case <-time.After(time.Second):
		require.Failf(t, "timed out waiting for watch-triggered sync to start", "watch calls=%d head=%d", watchCalls.Load(), namespaceHead.Load())
	}
	select {
	case <-secondWatch:
		require.Failf(t, "watch reopened before triggered sync finished", "watch calls=%d", watchCalls.Load())
	case <-time.After(150 * time.Millisecond):
	}

	release()
	select {
	case <-time.After(40 * time.Millisecond):
	case <-runCtx.Done():
	}
	require.Equal(t, int64(2), listCalls.Load())
	cancel()
	if err := <-runDone; err != nil {
		require.ErrorIs(t, err, context.Canceled)
	}
}
