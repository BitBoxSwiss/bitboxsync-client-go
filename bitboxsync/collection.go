// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"context"
	"fmt"

	"bitboxsync-client-go/protocol"
)

// Collection registers typed sync behavior for one namespace collection.
type Collection[T any] struct {
	engine      *Engine
	namespaceID string
	name        string
	codec       Codec[T]
	backend     ValueBackend[T]
}

// ID returns the namespace identifier.
func (n *Namespace) ID() string {
	return n.namespaceID
}

// OpenCollection constructs a typed collection helper bound to one namespace.
func OpenCollection[T any](namespace *Namespace, name string, cfg CollectionConfig[T]) (*Collection[T], error) {
	if cfg.Backend == nil {
		return nil, fmt.Errorf("%w for collection %q", ErrNoBackend, name)
	}
	if cfg.Codec == nil {
		cfg.Codec = JSONCodec[T]()
	}
	if cfg.Merge == nil {
		cfg.Merge = NoMerge[T]()
	}
	if err := namespace.engine.registerCollection(makeRegisteredCollection(
		namespace.namespaceID,
		name,
		cfg.Codec,
		cfg.Merge,
		cfg.Backend,
	)); err != nil {
		return nil, err
	}
	return &Collection[T]{
		engine:      namespace.engine,
		namespaceID: namespace.namespaceID,
		name:        name,
		codec:       cfg.Codec,
		backend:     cfg.Backend,
	}, nil
}

// Members lists the namespace members known to the server.
func (n *Namespace) Members(ctx context.Context) ([]protocol.NamespaceMember, error) {
	var members []protocol.NamespaceMember
	if err := n.engine.runAuthenticated(ctx, func() error {
		state := n.engine.identityStateSnapshot()
		resp, err := n.engine.client.GetMembers(ctx, state.AccessToken, n.namespaceID)
		if err != nil {
			return err
		}
		members = resp.Members
		return nil
	}); err != nil {
		return nil, err
	}
	return members, nil
}

// ResolveConflictWithValue resolves a stored conflict by choosing an explicit
// replacement value to upload on the next sync.
func (c *Collection[T]) ResolveConflictWithValue(ctx context.Context, key string, value T) error {
	if err := c.engine.withLogicalKeyLock(c.namespaceID, c.name, key, func() error {
		item, err := c.engine.store.GetItemByLogicalKey(ctx, c.engine.keyID, c.namespaceID, c.name, key)
		if err != nil {
			return err
		}
		if !item.Conflict {
			return nil
		}
		if err := c.backend.Set(ctx, key, value); err != nil {
			return err
		}
		clearItemConflict(&item)
		markItemDirty(&item)
		if err := c.engine.store.SaveItem(ctx, item); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// ResolveConflictPreferLocal resolves a stored conflict by keeping the local
// value queued for upload.
func (c *Collection[T]) ResolveConflictPreferLocal(ctx context.Context, key string) error {
	if err := c.engine.withLogicalKeyLock(c.namespaceID, c.name, key, func() error {
		item, err := c.engine.store.GetItemByLogicalKey(ctx, c.engine.keyID, c.namespaceID, c.name, key)
		if err != nil {
			return err
		}
		if !item.Conflict {
			return nil
		}
		if _, err := c.backend.Get(ctx, key); err != nil {
			return err
		}
		clearItemConflict(&item)
		markItemDirty(&item)
		if err := c.engine.store.SaveItem(ctx, item); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// ResolveConflictPreferRemote resolves a stored conflict by accepting the remote
// value and clearing local dirty state.
func (c *Collection[T]) ResolveConflictPreferRemote(ctx context.Context, key string) error {
	return c.engine.withLogicalKeyLock(c.namespaceID, c.name, key, func() error {
		item, err := c.engine.store.GetItemByLogicalKey(ctx, c.engine.keyID, c.namespaceID, c.name, key)
		if err != nil {
			return err
		}
		if !item.Conflict {
			return nil
		}
		value, err := c.codec.Decode(item.ConflictRemoteValue)
		if err != nil {
			return err
		}
		if err := c.backend.Set(ctx, key, value); err != nil {
			return err
		}
		markItemClean(&item, item.ConflictRemoteVersion, item.ConflictRemoteValue)
		if err := c.engine.store.SaveItem(ctx, item); err != nil {
			return err
		}
		return nil
	})
}

// makeMergeBytes adapts a typed merge function into the byte-oriented merge
// callback stored in the engine registry.
func makeMergeBytes[T any](codec Codec[T], merge MergeFunc[T]) func(key string, base *[]byte, local, remote []byte) ([]byte, bool, error) {
	return func(key string, base *[]byte, local, remote []byte) ([]byte, bool, error) {
		var baseValue *T
		if base != nil {
			decodedBase, err := codec.Decode(*base)
			if err != nil {
				return nil, false, fmt.Errorf("decode merge base: %w", err)
			}
			baseValue = &decodedBase
		}
		localValue, err := codec.Decode(local)
		if err != nil {
			return nil, false, fmt.Errorf("decode merge local: %w", err)
		}
		remoteValue, err := codec.Decode(remote)
		if err != nil {
			return nil, false, fmt.Errorf("decode merge remote: %w", err)
		}
		mergedValue, resolved, err := merge(key, baseValue, localValue, remoteValue)
		if err != nil {
			return nil, false, err
		}
		if !resolved {
			return nil, false, nil
		}
		encoded, err := codec.Encode(mergedValue)
		if err != nil {
			return nil, false, fmt.Errorf("encode merged value: %w", err)
		}
		return encoded, resolved, nil
	}
}

// makeRegisteredCollection adapts a typed app backend into byte-level closures
// used by the engine. Keeping this conversion in one place makes the sync path
// independent of generics while avoiding adapter interfaces with one caller.
func makeRegisteredCollection[T any](
	namespaceID string,
	name string,
	codec Codec[T],
	merge MergeFunc[T],
	backend ValueBackend[T],
) registeredCollection {
	return registeredCollection{
		namespaceID: namespaceID,
		name:        name,
		keys:        backend.Keys,
		snapshot: func(ctx context.Context) (map[string][]byte, error) {
			values, err := backend.Snapshot(ctx)
			if err != nil {
				return nil, err
			}
			encoded := make(map[string][]byte, len(values))
			for key, value := range values {
				valueBytes, err := codec.Encode(value)
				if err != nil {
					return nil, err
				}
				encoded[key] = bytes.Clone(valueBytes)
			}
			return encoded, nil
		},
		get: func(ctx context.Context, key string) ([]byte, error) {
			value, err := backend.Get(ctx, key)
			if err != nil {
				return nil, err
			}
			encoded, err := codec.Encode(value)
			if err != nil {
				return nil, err
			}
			return bytes.Clone(encoded), nil
		},
		set: func(ctx context.Context, key string, encoded []byte) error {
			value, err := codec.Decode(encoded)
			if err != nil {
				return err
			}
			return backend.Set(ctx, key, value)
		},
		setIfCurrent: func(ctx context.Context, key string, currentEncoded []byte, currentFound bool, encoded []byte) (bool, error) {
			value, err := codec.Decode(encoded)
			if err != nil {
				return false, err
			}
			conditional, ok := backend.(ConditionalValueBackend[T])
			if !ok {
				return true, backend.Set(ctx, key, value)
			}
			var current T
			if currentFound {
				decoded, err := codec.Decode(currentEncoded)
				if err != nil {
					return false, err
				}
				current = decoded
			}
			return conditional.SetIfCurrent(ctx, key, current, currentFound, value)
		},
		mergeBytes: makeMergeBytes(codec, merge),
	}
}
