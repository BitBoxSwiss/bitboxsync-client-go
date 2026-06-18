// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"bitboxsync-client-go/protocol"
	"bitboxsync-client-go/raw"
)

var namespaceWatchTimeoutReconnectJitter = 5 * time.Second

// runNamespaceWatch keeps one advisory long poll open while Run is active. The
// watch endpoint is only a trigger; polling remains the correctness fallback
// and SyncNow still performs the authoritative reconciliation.
func (e *Engine) runNamespaceWatch(ctx context.Context) {
	failures := 0
	for {
		timedOut, err := e.watchNamespacesOnce(ctx)
		if err == nil {
			failures = 0
			if timedOut {
				ok, _ := e.sleepOrDone(ctx, randomDuration(namespaceWatchTimeoutReconnectJitter))
				if !ok {
					return
				}
			}
			continue
		}
		if ctx.Err() != nil || errors.Is(err, ErrClosed) {
			return
		}
		if isNamespaceWatchUnsupported(err) {
			return
		}

		failures++
		e.emit(Event{Type: EventNamespaceWatchFailed, Err: err})
		interval := backoffPollInterval(e.cfg.PollInterval, e.cfg.MaxPollInterval, failures)
		ok, loginSucceeded := e.sleepOrDone(ctx, jitterPollInterval(interval))
		if !ok {
			return
		}
		if loginSucceeded {
			failures = 0
		}
	}
}

func (e *Engine) watchNamespacesOnce(ctx context.Context) (bool, error) {
	var resp *protocol.WatchNamespacesResponse
	err := e.runAuthenticated(ctx, func() error {
		knownHeads, err := e.knownNamespaceHeads(ctx)
		if err != nil {
			return err
		}
		state := e.identityStateSnapshot()
		resp, err = e.client.WatchNamespaces(ctx, state.AccessToken, protocol.WatchNamespacesRequest{
			KnownHeads: knownHeads,
		})
		return err
	})
	if err != nil {
		return false, err
	}
	if resp == nil {
		return false, fmt.Errorf("namespace watch returned no response")
	}
	if len(resp.Namespaces) == 0 {
		if !resp.TimedOut {
			return false, fmt.Errorf("namespace watch returned no changes without timing out")
		}
		return true, nil
	}
	// The watch response is only a hint that some visible namespace differs from
	// the checkpoint in the request. It can be stale by the time it arrives, for
	// example when this client already observed a recent local upload.
	needsSync, err := e.namespaceWatchNeedsSync(ctx, resp.Namespaces)
	if err != nil {
		return false, err
	}
	if !needsSync {
		return false, nil
	}
	// Ask Run to reconcile before opening the next watch so the next request
	// carries updated local namespace heads and the regular poll timer resets.
	if err := e.requestRunSync(ctx, resp.Namespaces); err != nil {
		return false, err
	}
	return false, nil
}

// namespaceWatchNeedsSync reports whether a watch response contains a namespace
// head that is still ahead of local state. Equal or older heads are already
// reflected locally and should only cause the watch loop to reconnect.
func (e *Engine) namespaceWatchNeedsSync(ctx context.Context, namespaces []protocol.NamespaceSummary) (bool, error) {
	knownHeads, err := e.knownNamespaceHeads(ctx)
	if err != nil {
		return false, err
	}
	for _, namespace := range namespaces {
		knownHead, ok := knownHeads[namespace.NamespaceID]
		switch {
		case !ok || knownHead < namespace.NamespaceHead:
			return true, nil
		case knownHead > namespace.NamespaceHead:
			return false, fmt.Errorf("%w for namespace %s", ErrRollback, namespace.NamespaceID)
		}
	}
	return false, nil
}

func (e *Engine) knownNamespaceHeads(ctx context.Context) (map[string]uint64, error) {
	namespaces, err := e.store.ListNamespaces(ctx, e.keyID)
	if err != nil {
		return nil, err
	}
	knownHeads := make(map[string]uint64, len(namespaces))
	for _, namespace := range namespaces {
		knownHeads[namespace.NamespaceID] = namespace.NamespaceHead
	}
	return knownHeads, nil
}

func isNamespaceWatchUnsupported(err error) bool {
	var apiErr *raw.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case 404, 405, 501:
		return true
	default:
		return false
	}
}

// sleepOrDone waits for the next namespace-watch reconnect. The second return
// value reports whether Login succeeded, in which case watch can drop its
// failure backoff and reconnect promptly.
func (e *Engine) sleepOrDone(ctx context.Context, duration time.Duration) (bool, bool) {
	if duration <= 0 {
		select {
		case <-ctx.Done():
			return false, false
		case <-e.closed:
			return false, false
		case <-e.loginSucceededWatch:
			return true, true
		default:
			return true, false
		}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, false
	case <-e.closed:
		return false, false
	case <-timer.C:
		return true, false
	case <-e.loginSucceededWatch:
		return true, true
	}
}

func randomDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	span := big.NewInt(int64(max) + 1)
	offset, err := rand.Int(rand.Reader, span)
	if err != nil {
		return max / 2
	}
	return time.Duration(offset.Int64())
}
