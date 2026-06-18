// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/BitBoxSwiss/bitboxsync-client-go/raw"
)

// Engine coordinates authentication, namespace reconciliation, local
// persistence, and conflict-aware sync.
type Engine struct {
	cfg      Config
	keyID    string
	keyIDRaw [protocol.KeyIDLength]byte
	store    Store
	client   *raw.Client
	identity raw.Identity
	events   chan Event
	wakeSync chan struct{}
	syncReqs chan syncRequest

	// Login uses these hints to shorten retry delays after an explicit app
	// reconnect succeeds.
	loginSucceededRun   chan struct{}
	loginSucceededWatch chan struct{}

	mu              sync.RWMutex
	identityState   IdentityState
	collections     map[string]registeredCollection
	logicalKeyLocks sync.Map

	syncMu       sync.Mutex
	authMu       sync.Mutex
	eventMu      sync.RWMutex
	activitySeq  atomic.Uint64
	idlePolling  atomic.Bool
	closeOnce    sync.Once
	closed       chan struct{}
	eventsClosed bool
}

// registeredCollection stores the byte-level callbacks the engine needs for one
// typed collection. OpenCollection builds these closures once from the public
// ValueBackend and Codec so the sync engine itself can stay non-generic.
type registeredCollection struct {
	namespaceID  string
	name         string
	keys         func(ctx context.Context) ([]string, error)
	snapshot     func(ctx context.Context) (map[string][]byte, error)
	get          func(ctx context.Context, key string) ([]byte, error)
	set          func(ctx context.Context, key string, value []byte) error
	setIfCurrent func(ctx context.Context, key string, current []byte, currentFound bool, value []byte) (bool, error)
	mergeBytes   func(key string, base *[]byte, local, remote []byte) ([]byte, bool, error)
}

// Namespace is a lightweight handle for namespace-scoped operations.
type Namespace struct {
	engine      *Engine
	namespaceID string
}

// Open constructs a sync engine using the provided client, identity, and store.
func Open(ctx context.Context, cfg Config) (*Engine, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}

	engine := &Engine{
		cfg:                 cfg,
		keyIDRaw:            protocol.KeyIDFromAuthPublicKey(cfg.Identity.AuthPublicKey()),
		store:               cfg.Store,
		client:              cfg.Client,
		identity:            cfg.Identity,
		events:              make(chan Event, cfg.EventBuffer),
		wakeSync:            make(chan struct{}, 1),
		syncReqs:            make(chan syncRequest),
		loginSucceededRun:   make(chan struct{}, 1),
		loginSucceededWatch: make(chan struct{}, 1),
		collections:         make(map[string]registeredCollection),
		closed:              make(chan struct{}),
	}
	engine.keyID = hex.EncodeToString(engine.keyIDRaw[:])
	engine.idlePolling.Store(cfg.IdlePolling)

	state, err := cfg.Store.LoadIdentity(ctx, engine.keyID)
	switch {
	case err == nil:
		engine.identityState = state
	case errors.Is(err, ErrNotFound):
		engine.identityState = IdentityState{
			KeyID: engine.keyID,
			Kind:  engine.identity.Kind(),
		}
	default:
		return nil, err
	}
	return engine, nil
}

// Close stops the engine and releases the configured store.
func (e *Engine) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.closed)
		e.syncMu.Lock()
		defer e.syncMu.Unlock()
		e.eventMu.Lock()
		e.eventsClosed = true
		close(e.events)
		e.eventMu.Unlock()
		err = e.store.Close()
	})
	return err
}

// Events returns important lifecycle/data/control events.
// Events are ordered and not dropped. If the caller does not read,
// the client may block.
func (e *Engine) Events() <-chan Event {
	return e.events
}

// KeyID returns the auth identity key ID bound to the engine.
func (e *Engine) KeyID() string {
	return e.keyID
}
