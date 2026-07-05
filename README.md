# BitBoxSync Go Client

This module is split into three layers:

- `protocol`: shared wire-format and crypto helpers used by both client and server.
- `raw`: direct HTTP client plus identity abstractions for signed intents, wrapped DEKs, and attestation. Its dummy keystore helper is deterministic test/demo code and must not be used for production identities.
- `bitboxsync`: a stateful local-first sync engine intended for app use.

The default persistence backend is [`storage/sqlite`](./storage/sqlite), but the sync engine depends only on the [`bitboxsync.Store`](./bitboxsync/types.go) interface, so apps can provide their own storage implementation.

## Intended app-facing API

Use the `bitboxsync` package in normal applications.

It handles:

- login and token refresh,
- default/shared namespace bootstrap,
- cached namespace DEKs,
- persisted namespace heads and item versions,
- local-first writes,
- background polling,
- conflict detection and merge hooks,
- resume-triggered sync.

Production apps normally keep their domain storage in the app and let
BitBoxSync persist only sync metadata. Existing app write paths should keep
writing to the app store. Collection backends expose snapshots so BitBoxSync can
detect local changes at sync time.

```go
client, _ := raw.New("http://localhost:8090", nil)
var identity raw.Identity // Provided by the app's keystore integration.
store, _ := sqlite.Open("bitboxsync.sqlite")

engine, _ := bitboxsync.Open(ctx, bitboxsync.Config{
    Client:       client,
    Identity:     identity,
    Store:        store,
    PollInterval: 30 * time.Second,
})
defer engine.Close()

defaultNS, _ := engine.DefaultNamespace(ctx)
_, _ = bitboxsync.OpenCollection(defaultNS, "account-labels", bitboxsync.CollectionConfig[string]{
    Codec:   bitboxsync.StringCodec(),
    Merge:   bitboxsync.PreferLocal[string](),
    Backend: appAccountLabelsBackend,
})
_, _ = bitboxsync.OpenCollection(defaultNS, "tx-note-buckets", bitboxsync.CollectionConfig[map[string]string]{
    Codec:   bitboxsync.JSONCodec[map[string]string](),
    Merge:   mergeTxNoteBucket,
    Backend: appTxNoteBucketBackend,
})
go engine.Run(ctx)

_ = appStore.RenameAccount("account:primary", "Savings")
_ = appStore.SetTxNote("txid", "memo")
engine.ScheduleSync()
```

The app-facing part of the backend is:

- `Keys(ctx)` to return the full active key scope for this collection,
- `Get(ctx, key)` to read one value for upload/records,
- `Set(ctx, key, value)` to apply remote values to app storage,
- `Snapshot(ctx)` to return current local values efficiently for sync-time
  reconciliation,
- `SetIfCurrent(ctx, key, current, currentFound, value)` to atomically apply
  remote values only if the app value has not changed since sync read it.

Collections register codecs, merge behavior, the value backend, and its key
scope with the engine. They are not an app storage facade: app features should
read and write their native storage directly, then call `engine.ScheduleSync()`
when prompt background sync is wanted.

For bucketed data such as transaction notes, implement `Snapshot` in one pass
over the app's native data and return one value per non-empty bucket. Sync
compares encoded snapshot values to its last clean base and uploads only changed
items.

Merge functions receive the logical `key`, `base *T`, `local T`, and
`remote T`. `base` is nil when no common base is known, for example on first
enable with existing local and remote values, after local sync metadata was
reset, or when two clients concurrently created the same logical key. The
collection's merge function decides whether that two-way collision can be
resolved automatically:

```go
func mergeTxNoteBucket(key string, base *map[string]string, local, remote map[string]string) (map[string]string, bool, error) {
    if base == nil {
        merged := make(map[string]string, len(local)+len(remote))
        maps.Copy(merged, remote)
        maps.Copy(merged, local) // local wins when the same tx note differs
        return merged, true, nil
    }

    // Normal three-way merge using *base, local, and remote.
}
```

Return `resolved=false` when the collection cannot safely merge without a base.
The engine will keep the local value, store the remote value as conflict
metadata, and stop uploading that item until the app resolves the conflict.
TODO: Add a local-only conflict listing/inspection API if an app needs manual
conflict UI. The current intended integrations should resolve all conflicts in
their merge functions.

`Run` polls at `PollInterval` with randomized jitter in normal foreground mode,
and backs off repeated transient failures up to `MaxPollInterval`. It does not
infer idleness from unchanged polls. Apps that enter an explicit background,
idle, or watch-only state can opt into slower quiet-poll backoff with
`engine.SetIdlePolling(true)`, and should switch back with
`engine.SetIdlePolling(false)` when foreground freshness is expected again.
After an app-owned value write, call `engine.ScheduleSync()` when prompt
background upload is desired. It only wakes the `Run` loop, coalesces repeated
calls, and does not perform network work itself. After bulk writes, call it once
when the batch has finished. Use `engine.SyncNow(ctx)` for explicit foreground
syncs where the caller waits for the result. After an app-driven login or
device reconnect, call `engine.Login(ctx)` to reset background failure backoff
and wake namespace watch when it is waiting to reconnect.

## Shared namespace invites

Shared namespace membership uses rendezvous invites. An existing member creates
an invite, a prospective member scans/submits a signed join request, and an
existing member approves that request by wrapping the namespace DEK to the
requester's wrapping key.

```go
shared, _ := alice.CreateSharedNamespace(ctx)

invite, _ := shared.CreateInvite(ctx, bitboxsync.NamespaceInviteOptions{
    ServerOrigin: "https://sync.example",
    TTL:          10 * time.Minute,
})
inviteURI, _ := bitboxsync.InviteURI(invite)

scannedInvite, _ := bitboxsync.ParseInviteURI(inviteURI)
_, _ = bob.SubmitJoinRequest(ctx, scannedInvite, bitboxsync.NamespaceJoinRequestOptions{})

requests, _ := shared.JoinRequests(ctx)
_ = shared.ApproveJoinRequest(ctx, invite, requests[0])

bobShared, _ := bob.JoinNamespace(ctx, shared.ID())
_ = bobShared
```

The invite token contains routing, invite ID, expiry, and the invite secret, but
not the namespace DEK. Apps that approve join requests must keep the raw invite
token locally until pending requests are approved or the invite is revoked.

## Collections and active key scope

Because item IDs are opaque HMACs of logical keys, the engine cannot infer unknown logical keys from the server by itself.

Every collection backend must provide `Keys()`. It returns the full active key
scope for the collection: keys with local values and keys that may only exist
remotely. The engine derives item IDs for those keys, matches them against the
server's namespace item map, and materializes remote-only values into the
backend.

`Keys()` should return the full current active key set on every call, not only newly added keys. Keys that are not returned are outside the current sync scope: the engine will not download or upload them until they are returned again.

The engine stores a hash of the active scope with the local namespace checkpoint. It fetches the namespace item map when either the server namespace head changed or the active scope hash changed. This lets staged onboarding and account reactivation reconcile remote items even if the namespace head is unchanged.

## Value storage

Collections always store current values in a `bitboxsync.ValueBackend`. Apps
with existing data stores can use those stores directly and let BitBoxSync
persist only sync metadata:

```go
_, _ = bitboxsync.OpenCollection(defaultNS, "notes", bitboxsync.CollectionConfig[string]{
    Codec:   bitboxsync.StringCodec(),
    Merge:   bitboxsync.PreferLocal[string](),
    Backend: existingNotesBackend,
})

// App features keep using app storage directly.
_ = existingNotesStore.SetTxNote(txID, "memo")

// Run reconciles existingNotesBackend.Snapshot() automatically.
engine.ScheduleSync()

// Use SyncNow instead when the caller should wait for the sync result.
// _ = engine.SyncNow(ctx)
```

`CollectionConfig.Backend` stores typed values and owns the collection's active
key scope. The sync collection owns the codec boundary: it encodes backend
values before encryption/upload and decodes remote values before writing them
into the backend. The backend's `Snapshot` method is reconciled at the start of
each sync pass.

Backend requirements:

- `Get(ctx, key)` returns the current typed value or `bitboxsync.ErrNotFound`.
- `Set(ctx, key, value)` atomically replaces one key's value.
- After `Set` returns nil, a later `Get` for the same key should return the new value.
- Backends must be safe for concurrent calls.
- `Set` is called by sync when applying remote values.
- App-owned stores that can be written while sync is running should implement
  `bitboxsync.ConditionalValueBackend`. Its `SetIfCurrent` method must compare
  and replace under the same lock or transaction used by app writes.
- `Keys()` must return stable collection-local logical keys for the current active sync scope.
- `Snapshot()` must return current existing values by collection-local logical
  key. It should be efficient enough to call at the start of every sync pass.

Open collections before starting background `Run` so the engine has the value backends needed to apply remote changes and flush dirty metadata.

Every `SyncNow` or `Run` pass compares the encoded snapshot values to the last
clean sync base. New or changed values are marked dirty before remote changes
are pulled and before uploads are flushed. This lets app write paths avoid
BitBoxSync calls other than scheduling a sync.

Before applying a remote value to a clean item, the engine re-reads the current
backend value. If it differs from the stored clean base, the value is treated as
a local edit and merged instead of overwritten. For full race protection, the
backend must also implement `ConditionalValueBackend`: otherwise a direct app
write that lands after this re-read but before `Set` can still be overwritten by
the remote apply. Backends whose values can change outside BitBoxSync while sync
is running should treat `SetIfCurrent` as required for production correctness.

`bitboxsync.NewMemoryValueBackend` is available for tests, demos, and short-lived tools. Durable apps should provide a backend backed by their own storage.

## Storage model

The sync layer persists:

- bearer token and expiry,
- default namespace ID,
- namespace DEKs,
- namespace heads,
- item versions,
- dirty-write queue state,
- last clean base values used for snapshot comparison and conflict merge,
- unresolved conflict state.

When an app disables sync for one identity, it can call
`Store.ForgetIdentitySecrets(ctx, keyID)` to clear locally cached bearer tokens
and unwrapped namespace DEKs for that identity while keeping namespace heads,
item versions, clean base values, dirty state, and conflict metadata. Keeping
that metadata lets a later re-enable reconcile local and remote changes without
turning the next sync into a first-sync collision.

When an app detects `bitboxsync.ErrRollback`, it can call
`Store.ResetSyncState(ctx, keyID)` to clear namespace and item metadata for that
identity while keeping the bearer token and expiry. This is a store-level repair
step: stop the current engine run, stop using the current `Engine`, `Namespace`,
and `Collection` handles, reset the store state, then construct a fresh engine
and recreate the handles. The fresh engine can recreate the default namespace
cache and re-bootstrap item state from the server. If closing the old engine also
closes the store handle, reopen the store before resetting or reset through a
separate store handle.

The bundled SQLite backend is suitable for sync metadata. It writes each metadata row with a single `INSERT ... ON CONFLICT DO UPDATE` statement, so each `SaveItem` is atomic for one item, but it does not group multiple items into one transaction.

The engine reads and writes collection values one key at a time after snapshot
reconciliation. Snapshot reconciliation may inspect many app values locally, but
it only marks items dirty when the encoded value differs from the stored clean
base or when the item is new. Remote changes are applied per item, and dirty
uploads are flushed per item. Known collection items are serialized by logical
key (`namespace + collection + key`).
When `ConditionalValueBackend` is available, remote application is conditional
on the backend value still matching the value sync just read. This closes the
small race between clean-value verification and remote write for app-owned
stores.
Unknown remote item IDs are emitted as unknown because they cannot be mapped
back to a value backend key. There is no multi-key value-backend transaction
requirement.

Apps must provide `bitboxsync.ValueBackend` for collection values and can
implement `bitboxsync.Store` too if they need to replace the sync metadata store
itself. Snapshot-backed integrations avoid cross-store write transactions: app
writes update app storage, and later sync passes reconcile the current snapshot.
