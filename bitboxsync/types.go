// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/BitBoxSwiss/bitboxsync-client-go/raw"
)

var (
	ErrNotFound             = errors.New("bitboxsync: not found")
	ErrRollback             = errors.New("bitboxsync: rollback detected")
	ErrClosed               = errors.New("bitboxsync: engine closed")
	ErrNoDefault            = errors.New("bitboxsync: default namespace not provisioned")
	ErrNoBackend            = errors.New("bitboxsync: collection value backend required")
	ErrCollectionRegistered = errors.New("bitboxsync: collection already registered")
)

// Config controls engine dependencies and background sync behavior.
type Config struct {
	// Client is the raw BitBoxSync API client used for all network requests. It
	// is required.
	Client *raw.Client
	// Identity provides the auth signing, attestation, and private DEK unwrap
	// operations needed by the engine. It is required.
	Identity raw.Identity
	// Store persists identity state, namespaces, item metadata, dirty state, and
	// conflicts across runs. It is required.
	Store Store
	// PollInterval is how often Run performs fallback background sync passes.
	// Values less than or equal to zero default to 5 minutes.
	PollInterval time.Duration
	// IdlePolling starts Run in explicit idle polling mode. Idle mode is intended
	// for app-controlled background or watch-only states where slower remote
	// change detection is acceptable. It can be changed later with
	// Engine.SetIdlePolling.
	IdlePolling bool
	// MaxPollInterval is the longest delay Run will use after explicit idle
	// polling or failed polling backs off. Values less than PollInterval default
	// to the larger of 60 minutes and PollInterval.
	MaxPollInterval time.Duration
	// DisableNamespaceWatch disables the advisory long-poll namespace watch loop.
	// When enabled, Run still keeps its polling timer as a correctness fallback.
	DisableNamespaceWatch bool
	// RefreshSkew is how long before token expiry the engine proactively refreshes
	// the bearer token. Values less than or equal to zero default to 24 hours.
	RefreshSkew time.Duration
	// EventBuffer is the size of the buffered Events channel. Values less than or
	// equal to zero default to 64.
	EventBuffer int
	// InviteTTL is the default lifetime used by CreateInvite when the caller
	// passes a non-positive ttl. Values less than or equal to zero default to 10
	// minutes.
	InviteTTL time.Duration
}

// IdentityState stores persisted authentication and default-namespace state.
type IdentityState struct {
	// KeyID identifies the auth identity this state belongs to.
	KeyID string
	// Kind is the auth-key kind, currently expected to be "keystore".
	Kind string
	// AccessToken is the last bearer token issued for this identity.
	AccessToken string
	// TokenExpiry is when AccessToken expires server-side.
	TokenExpiry time.Time
	// DefaultNamespaceID is the cached default namespace identifier for this
	// identity.
	DefaultNamespaceID string
	// UpdatedAt records when this state was last written locally.
	UpdatedAt time.Time
}

// NamespaceState stores cached namespace metadata and the unwrapped namespace
// DEK.
type NamespaceState struct {
	// KeyID identifies the auth identity this namespace cache entry belongs to.
	KeyID string
	// NamespaceID is the hex-encoded namespace identifier.
	NamespaceID string
	// Kind is the namespace kind, such as "default" or "shared".
	Kind string
	// NamespaceHead is the highest namespace head observed locally.
	NamespaceHead uint64
	// ActiveScopeHash identifies the set of active logical keys that was
	// reconciled at NamespaceHead. It is empty when no collection is registered.
	ActiveScopeHash string
	// DEK is the unwrapped namespace data-encryption key cached locally.
	DEK []byte
	// UpdatedAt records when this state was last written locally.
	UpdatedAt time.Time
}

// NamespaceInviteOptions controls creation of one shared-namespace invite.
type NamespaceInviteOptions struct {
	// ServerOrigin is the canonical public server origin encoded into the invite
	// QR. It must match one of the server's configured public origins.
	ServerOrigin string
	// InviteID is an optional caller-generated lowercase-hex invite ID. Leave it
	// empty to generate a fresh random ID during CreateInvite.
	InviteID string
	// InviteSecret is an optional caller-generated unpadded base64url invite
	// secret. Leave it empty to generate a fresh random secret during
	// CreateInvite.
	InviteSecret string
	// TTL controls invite lifetime. Non-positive values use Config.InviteTTL.
	TTL time.Duration
	// MaxAccepted caps successful first-time approvals through this invite.
	// Non-positive values use the protocol default.
	MaxAccepted int
}

// NamespaceJoinRequestOptions controls submission of one namespace join request.
type NamespaceJoinRequestOptions struct {
	// TTL controls join-request lifetime. Non-positive values use the protocol
	// maximum.
	TTL time.Duration
	// ExpiresAt is an optional absolute Unix timestamp in seconds. Leave it zero
	// to derive expiry from TTL.
	ExpiresAt int64
}

// ItemState stores the local sync metadata for one item, including merge base
// and conflict metadata. Current values belong to the collection's
// ValueBackend.
type ItemState struct {
	// KeyID identifies the auth identity this item cache entry belongs to.
	KeyID string
	// NamespaceID is the hex-encoded namespace identifier.
	NamespaceID string
	// Collection is the logical collection name for the item.
	Collection string
	// Key is the logical key within Collection.
	Key string
	// ItemID is the opaque hex-encoded item identifier derived from Collection
	// and Key.
	ItemID string
	// Version is the highest item version known locally.
	Version uint64
	// BaseVersion is the version associated with BaseValue.
	BaseVersion uint64
	// BaseValue is the last remote value that local edits were based on.
	BaseValue []byte
	// Dirty reports whether the current value still needs to be uploaded.
	Dirty bool
	// Conflict reports whether automatic merge failed and manual resolution is
	// required.
	Conflict bool
	// ConflictRemoteVersion is the remote version involved in the unresolved
	// conflict.
	ConflictRemoteVersion uint64
	// ConflictRemoteValue is the remote value involved in the unresolved
	// conflict.
	ConflictRemoteValue []byte
	// UpdatedAt records when this state was last written locally.
	UpdatedAt time.Time
}

// Store persists engine state across runs.
type Store interface {
	// Close releases any resources held by the store. It must be safe to call
	// once during engine shutdown.
	Close() error
	// LoadIdentity loads the persisted auth/session state for keyID. It must
	// return ErrNotFound when no identity state exists yet.
	LoadIdentity(ctx context.Context, keyID string) (IdentityState, error)
	// SaveIdentity persists the latest auth/session state for an auth identity.
	// Implementations must replace the prior state atomically for the same keyID.
	SaveIdentity(ctx context.Context, state IdentityState) error
	// GetNamespace loads cached metadata and secrets for one namespace. It must
	// return ErrNotFound when the namespace has not been cached locally.
	GetNamespace(ctx context.Context, keyID, namespaceID string) (NamespaceState, error)
	// ListNamespaces returns all cached namespaces for the given auth identity.
	// Implementations should not filter by namespace kind.
	ListNamespaces(ctx context.Context, keyID string) ([]NamespaceState, error)
	// SaveNamespace persists the latest metadata for one namespace. The save must
	// upsert by the tuple of keyID and namespaceID.
	SaveNamespace(ctx context.Context, state NamespaceState) error
	// ForgetIdentitySecrets clears locally cached secrets for one identity, such
	// as bearer tokens and unwrapped namespace DEKs, while preserving namespace
	// and item metadata used for later merge reconciliation.
	ForgetIdentitySecrets(ctx context.Context, keyID string) error
	// GetItemByID loads an item by its opaque item ID. It must return ErrNotFound
	// when the item is unknown locally.
	GetItemByID(ctx context.Context, keyID, namespaceID, itemID string) (ItemState, error)
	// GetItemByLogicalKey loads an item by the human-readable collection/key
	// tuple. It must return ErrNotFound when the item is unknown locally.
	GetItemByLogicalKey(ctx context.Context, keyID, namespaceID, collection, key string) (ItemState, error)
	// ListNamespaceItems returns all locally cached items for a namespace,
	// including dirty or conflicted entries.
	ListNamespaceItems(ctx context.Context, keyID, namespaceID string) ([]ItemState, error)
	// ListDirtyItems returns every item with unapplied local changes for keyID.
	// Implementations should include conflicted items so callers can decide how
	// to handle them.
	ListDirtyItems(ctx context.Context, keyID string) ([]ItemState, error)
	// SaveItem persists one item snapshot, including its base value, dirty flag,
	// and conflict metadata. The save must upsert by the tuple of keyID,
	// namespaceID, and itemID.
	SaveItem(ctx context.Context, state ItemState) error
}

type EventType string

const (
	// EventAuthLoginRequired is emitted when the engine needs a fresh login
	// before authenticated work can continue.
	EventAuthLoginRequired EventType = "auth-login-required"
	// EventAuthRefreshRecommended is emitted when the current bearer token is
	// still valid but close enough to expiry that callers should prompt the user
	// to reconnect.
	EventAuthRefreshRecommended EventType = "auth-refresh-recommended"
	// EventAuthSessionReady is emitted after login or refresh stores a usable
	// bearer token.
	EventAuthSessionReady EventType = "auth-session-ready"
	// EventSyncStarted is emitted when a sync pass begins.
	EventSyncStarted EventType = "sync-started"
	// EventSyncFinished is emitted when a sync pass completes successfully.
	EventSyncFinished EventType = "sync-finished"
	// EventSyncFailed is emitted when a sync pass terminates with an error.
	EventSyncFailed EventType = "sync-failed"
	// EventNamespaceWatchFailed is emitted when the advisory namespace watch loop
	// encounters a transient error. Polling continues to provide correctness.
	EventNamespaceWatchFailed EventType = "namespace-watch-failed"
	// EventNamespaceChanged is emitted when a namespace head was reconciled.
	EventNamespaceChanged EventType = "namespace-changed"
	// EventItemChanged is emitted when local state for an item changed due to
	// sync, merge, or conflict refresh.
	EventItemChanged EventType = "item-changed"
	// EventItemDownloaded is emitted when a remote item value was applied to
	// the local value backend.
	EventItemDownloaded EventType = "item-downloaded"
	// EventItemUploaded is emitted after a dirty local item was successfully
	// uploaded to the server.
	EventItemUploaded EventType = "item-uploaded"
	// EventItemQueued is emitted when a local write is staged for upload.
	EventItemQueued EventType = "item-queued"
	// EventConflictDetected is emitted when automatic merge cannot resolve a
	// local-versus-remote divergence.
	EventConflictDetected EventType = "conflict-detected"
	// EventUnknownRemoteItem is emitted when the server reports an item ID the
	// engine cannot yet map back to a logical key.
	EventUnknownRemoteItem EventType = "unknown-remote-item"
)

// Event records a notable sync-engine state transition.
type Event struct {
	// Type names the event category.
	Type EventType
	// NamespaceID identifies the namespace involved in the event, when
	// applicable.
	NamespaceID string
	// Collection identifies the collection involved in the event, when
	// applicable.
	Collection string
	// Key identifies the logical key involved in the event, when applicable.
	Key string
	// ItemID identifies the opaque item involved in the event, when applicable.
	ItemID string
	// Err holds the underlying error for failure events.
	Err error
	// TokenExpiresAt records the bearer-token expiry for auth session events.
	TokenExpiresAt time.Time
	// At records when the event was emitted.
	At time.Time
}

// Codec translates typed collection values to and from encrypted payload
// bytes.
type Codec[T any] interface {
	// Encode serializes a typed collection value into the bytes stored in the
	// encrypted item payload. Implementations must be deterministic for equal
	// inputs so conflict handling remains predictable.
	Encode(T) ([]byte, error)
	// Decode parses bytes previously produced by Encode. Implementations must
	// reject malformed payloads rather than silently producing partial values.
	Decode([]byte) (T, error)
}

// MergeFunc resolves a conflict between the current local value and a remote
// value for key.
//
// base points to the last value known to be shared by both sides. It is nil
// when no common base is known, for example during first enable, after local
// sync metadata was reset, or when two clients concurrently created the same
// logical key. Merge functions that can safely resolve that two-way collision
// may still return resolved=true. Merge functions that need a true three-way
// base should return resolved=false when base is nil.
//
// Implementations should treat base, local, and remote as read-only inputs. If
// T contains maps, slices, or pointers, return an owned value before mutating it.
type MergeFunc[T any] func(key string, base *T, local, remote T) (merged T, resolved bool, err error)

// ValueBackend stores collection values outside the sync store.
//
// The sync engine still owns item IDs, versions, merge bases, dirty state, and
// conflicts in Store. Backends own current typed collection values.
//
// Set is the storage primitive used by sync-applied remote values.
//
// Implementations must be safe for concurrent calls. Set must
// atomically replace the value for one key, and a later Get for the same key
// should return the new value after Set returns nil. The sync engine
// never asks a backend to update multiple keys in one call.
//
// The engine reconciles Snapshot at the start of each sync pass. For each
// returned key, it encodes the value with the collection codec and compares it
// to the last clean value stored in sync metadata. New or changed values are
// marked dirty before remote pull/upload. This lets apps keep their normal
// storage write paths and let sync observe the current app state at sync time.
//
// The ValueBackend and Store are separate durability domains.
type ValueBackend[T any] interface {
	// Keys returns the full active key scope for this collection. It must include
	// keys with local values and keys that may exist only remotely. The engine
	// derives candidate item IDs from these keys, because server item IDs are
	// opaque and cannot be reversed into logical keys.
	//
	// Implementations may return keys that do not currently exist remotely, but
	// they must return stable collection-local logical keys and should be safe to
	// call repeatedly during sync. Each call must return the full current active
	// key set, not a delta from the previous call. Keys that are not returned are
	// outside the current sync scope and are ignored until returned again.
	Keys(ctx context.Context) ([]string, error)
	// Snapshot returns collection-local logical keys mapped to current typed
	// values that exist in the app store. Implementations should build the
	// snapshot in one efficient pass where possible and must return values safe
	// for the codec to read. Snapshot keys should be a subset of Keys. BitBoxSync
	// currently has no item-deletion protocol, so omitted snapshot keys are not
	// uploaded as deletions.
	Snapshot(ctx context.Context) (map[string]T, error)
	// Get returns the current typed value for key. It must return ErrNotFound
	// when the value is absent from the external store.
	Get(ctx context.Context, key string) (T, error)
	// Set stores the current typed value for key.
	Set(ctx context.Context, key string, value T) error
}

// ConditionalValueBackend is an optional ValueBackend extension for app-owned
// stores that can be written outside BitBoxSync.
//
// SetIfCurrent must atomically compare the currently stored value for key to
// current/currentFound and replace it with value only when they still match. It
// returns replaced=false when another app write won the race. The sync engine
// then leaves the item dirty and retries through normal merge/upload handling
// instead of overwriting the app's newer value.
//
// App-owned production backends that allow writes outside BitBoxSync should
// implement this interface. If they do not, remote apply falls back to Set after
// a best-effort re-read. That fallback can still overwrite an app write that
// lands after the re-read and before Set.
type ConditionalValueBackend[T any] interface {
	SetIfCurrent(ctx context.Context, key string, current T, currentFound bool, value T) (replaced bool, err error)
}

// CollectionConfig defines the codec, merge policy, and storage backend for a
// collection.
type CollectionConfig[T any] struct {
	// Codec serializes values to and from encrypted item payload bytes. When nil,
	// OpenCollection defaults it to JSONCodec.
	Codec Codec[T]
	// Merge resolves three-way conflicts for this collection. When nil,
	// OpenCollection defaults it to NoMerge.
	Merge MergeFunc[T]
	// Backend stores current typed values in an app-owned data store. It is
	// required. Backend.Keys defines the active sync scope, and Backend.Snapshot
	// returns the local values reconciled during each sync pass.
	Backend ValueBackend[T]
}

// withDefaults validates a sync engine config and applies default values for
// optional fields.
func (c Config) withDefaults() (Config, error) {
	if c.Client == nil {
		return Config{}, fmt.Errorf("sync client is required")
	}
	if c.Identity == nil {
		return Config{}, fmt.Errorf("sync identity is required")
	}
	if c.Store == nil {
		return Config{}, fmt.Errorf("sync store is required")
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 5 * time.Minute
	}
	if c.MaxPollInterval < c.PollInterval {
		c.MaxPollInterval = max(60*time.Minute, c.PollInterval)
	}
	if c.RefreshSkew <= 0 {
		c.RefreshSkew = 24 * time.Hour
	}
	if c.EventBuffer <= 0 {
		c.EventBuffer = 64
	}
	if c.InviteTTL <= 0 {
		c.InviteTTL = protocol.DefaultInviteTTL
	}
	return c, nil
}
