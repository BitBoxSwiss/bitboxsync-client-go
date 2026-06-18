// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
)

type syncRequest struct {
	// namespaces is the watch response that triggered the request. Run rechecks
	// it before syncing because another sync pass may have already advanced the
	// local heads while this request was waiting.
	namespaces []protocol.NamespaceSummary
	done       chan error
}

// SetIdlePolling controls whether Run uses the slower idle polling backoff
// policy after successful polls with no sync activity. Apps should enable this
// only for explicit background, idle, or watch-only states where slower remote
// change detection is acceptable. Changing the mode wakes Run so the new
// cadence can take effect promptly.
func (e *Engine) SetIdlePolling(idle bool) {
	e.idlePolling.Store(idle)
	e.scheduleSync()
}

// IdlePolling reports whether Run is currently using explicit idle polling
// behavior after quiet successful polls.
func (e *Engine) IdlePolling() bool {
	return e.idlePolling.Load()
}

// ScheduleSync asks Run to perform a sync pass soon.
//
// The wake-up is coalesced and non-blocking: if a sync is already queued, this
// call does not queue another one. ScheduleSync does not perform network work
// itself and is safe to call after app-owned value writes. Use SyncNow when the
// caller needs to wait for a foreground sync result.
func (e *Engine) ScheduleSync() {
	e.scheduleSync()
}

// Run starts the background polling loop and keeps syncing until ctx is done or
// the engine is closed.
func (e *Engine) Run(ctx context.Context) error {
	interval, failures, idlePolls := e.cfg.PollInterval, 0, 0
	resetBackoff := func() {
		failures = 0
		idlePolls = 0
		interval = e.cfg.PollInterval
	}
	recordResult := func(activity bool, err error, resetOnSuccess bool) {
		if err != nil {
			failures++
			idlePolls = 0
			interval = backoffPollInterval(e.cfg.PollInterval, e.cfg.MaxPollInterval, failures)
			return
		}
		failures = 0
		if activity || resetOnSuccess {
			idlePolls = 0
			interval = e.cfg.PollInterval
			return
		}
		if !e.idlePolling.Load() {
			idlePolls = 0
			interval = e.cfg.PollInterval
			return
		}
		idlePolls++
		interval = idlePollInterval(e.cfg.PollInterval, e.cfg.MaxPollInterval, idlePolls)
	}

	activity, err := e.syncNowWithActivity(ctx)
	recordResult(activity, err, false)

	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	if !e.cfg.DisableNamespaceWatch {
		go e.runNamespaceWatch(watchCtx)
	}

	timer := time.NewTimer(jitterPollInterval(interval))
	defer timer.Stop()
	runSync := func(resetOnSuccess bool) error {
		activity, err := e.syncNowWithActivity(ctx)
		recordResult(activity, err, resetOnSuccess)
		timer.Reset(jitterPollInterval(interval))
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.closed:
			return ErrClosed
		case <-timer.C:
			_ = runSync(false)
		case <-e.wakeSync:
			_ = runSync(true)
		case <-e.loginSucceededRun:
			// A foreground/authenticated call succeeded, so auth is usable again.
			// Drop accumulated failure backoff without doing a duplicate sync.
			resetBackoff()
			timer.Reset(jitterPollInterval(interval))
		case req := <-e.syncReqs:
			// Watch notifications are advisory and may report this client's own
			// recent upload. Re-read local heads here, after any in-flight Run sync
			// has completed, to avoid turning that self-notification into a second
			// full sync pass.
			if len(req.namespaces) > 0 {
				needsSync, err := e.namespaceWatchNeedsSync(ctx, req.namespaces)
				if err != nil {
					req.done <- err
					continue
				}
				if !needsSync {
					req.done <- nil
					continue
				}
			}
			req.done <- runSync(true)
		}
	}
}

// SyncNow performs one full foreground sync pass.
//
// Conceptually, the engine maintains a local-first replica in the configured
// store and reconciles that replica with the server in three phases:
//
//  1. Ensure authentication is usable by logging in or refreshing the bearer
//     token as needed.
//  2. Reconcile registered collection snapshots into dirty item metadata.
//  3. Pull remote namespace and item state. Namespace heads act as cheap
//     invalidation signals, backend keys map logical keys to opaque item
//     IDs, and changed remote items are applied, merged with local dirty state,
//     or recorded as conflicts.
//  4. Push local dirty items with optimistic concurrency. Writes use the cached
//     item version as If-Match, bind the target version into the item's AAD,
//     and fall back to fetch/merge/conflict handling on precondition failures.
//
// Run simply repeats this algorithm on a poll timer or explicit wake-up signal.
func (e *Engine) SyncNow(ctx context.Context) error {
	e.syncMu.Lock()
	defer e.syncMu.Unlock()

	if e.isClosed() {
		return ErrClosed
	}
	e.emit(Event{Type: EventSyncStarted})

	if err := e.runAuthenticated(ctx, func() error {
		if err := e.reconcileLocalSnapshots(ctx); err != nil {
			return err
		}
		if err := e.syncNamespaces(ctx); err != nil {
			return err
		}
		if err := e.flushDirtyItems(ctx); err != nil {
			return err
		}
		return nil
	}); err != nil {
		e.emit(Event{Type: EventSyncFailed, Err: err})
		return err
	}

	e.emit(Event{Type: EventSyncFinished})
	return nil
}

func (e *Engine) syncNowWithActivity(ctx context.Context) (bool, error) {
	before := e.activitySeq.Load()
	err := e.SyncNow(ctx)
	return e.activitySeq.Load() != before, err
}

// scheduleSync wakes the background loop so it performs an additional sync
// pass.
func (e *Engine) scheduleSync() {
	signal(e.wakeSync)
}

func (e *Engine) requestRunSync(ctx context.Context, namespaces []protocol.NamespaceSummary) error {
	req := syncRequest{
		namespaces: namespaces,
		done:       make(chan error, 1),
	}
	select {
	case e.syncReqs <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-e.closed:
		return ErrClosed
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-e.closed:
		return ErrClosed
	}
}

func (e *Engine) isClosed() bool {
	select {
	case <-e.closed:
		return true
	default:
		return false
	}
}

func idlePollInterval(base, max time.Duration, idlePolls int) time.Duration {
	// Keep the configured foreground cadence for the first few quiet polls, then
	// double every three additional idle polls up to the configured cap.
	return cappedDoubledInterval(base, max, idlePolls/3)
}

func backoffPollInterval(base, max time.Duration, failures int) time.Duration {
	if failures <= 0 {
		return base
	}
	return cappedDoubledInterval(base, max, failures)
}

func cappedDoubledInterval(base, max time.Duration, doublings int) time.Duration {
	if base <= 0 {
		return 0
	}
	if max < base {
		max = base
	}
	interval := base
	for range doublings {
		if interval >= max {
			return max
		}
		if interval > max/2 {
			return max
		}
		interval *= 2
	}
	if interval > max {
		return max
	}
	return interval
}

func jitterPollInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	jitter := interval / 10
	if jitter <= 0 {
		return interval
	}
	span := big.NewInt(int64(2*jitter + 1))
	offset, err := rand.Int(rand.Reader, span)
	if err != nil {
		return interval
	}
	return interval - jitter + time.Duration(offset.Int64())
}
