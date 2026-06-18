// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"bitboxsync-client-go/protocol"
)

// DefaultNamespace returns the caller's default namespace, creating it when
// needed.
func (e *Engine) DefaultNamespace(ctx context.Context) (*Namespace, error) {
	var namespace *Namespace
	if err := e.runAuthenticated(ctx, func() error {
		var err error
		namespace, err = e.defaultNamespace(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	return namespace, nil
}

func (e *Engine) defaultNamespace(ctx context.Context) (*Namespace, error) {
	state := e.identityStateSnapshot()
	if state.DefaultNamespaceID != "" {
		if _, err := e.ensureNamespaceReady(ctx, state.DefaultNamespaceID, protocol.NamespaceKindDefault); err != nil {
			return nil, err
		}
		return &Namespace{engine: e, namespaceID: state.DefaultNamespaceID}, nil
	}

	namespaceIDRaw, err := protocol.RandomNamespaceID()
	if err != nil {
		return nil, err
	}
	namespaceDEK, err := protocol.RandomNamespaceDEK()
	if err != nil {
		return nil, err
	}
	wrappedDEK, err := wrapNamespaceDEKFor(hex.EncodeToString(namespaceIDRaw), namespaceDEK, e.identity.WrapPublicKey())
	if err != nil {
		return nil, err
	}

	resp, err := e.client.EnsureDefaultNamespace(ctx, state.AccessToken, protocol.EnsureDefaultNamespaceRequest{
		ProposedNamespaceID: hex.EncodeToString(namespaceIDRaw),
		WrappedDEK:          protocol.EncodeBase64(wrappedDEK),
	})
	if err != nil {
		return nil, err
	}

	var dek []byte
	if resp.Created {
		dek = bytes.Clone(namespaceDEK)
	} else {
		serverWrappedDEK, err := protocol.DecodeBase64("wrappedDek", resp.WrappedDEK)
		if err != nil {
			return nil, err
		}
		dek, err = e.unwrapNamespaceDEK(ctx, resp.NamespaceID, serverWrappedDEK)
		if err != nil {
			return nil, err
		}
	}

	state.DefaultNamespaceID = resp.NamespaceID
	state.UpdatedAt = time.Now().UTC()
	if err := e.saveIdentityState(ctx, state); err != nil {
		return nil, err
	}
	if err := e.store.SaveNamespace(ctx, NamespaceState{
		KeyID:         e.keyID,
		NamespaceID:   resp.NamespaceID,
		Kind:          resp.Kind,
		NamespaceHead: 0,
		DEK:           bytes.Clone(dek),
		UpdatedAt:     time.Now().UTC(),
	}); err != nil {
		return nil, err
	}
	return &Namespace{engine: e, namespaceID: resp.NamespaceID}, nil
}

// CreateSharedNamespace creates a new shared namespace and caches its DEK
// locally.
func (e *Engine) CreateSharedNamespace(ctx context.Context) (*Namespace, error) {
	var namespace *Namespace
	if err := e.runAuthenticated(ctx, func() error {
		var err error
		namespace, err = e.createSharedNamespace(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	return namespace, nil
}

func (e *Engine) createSharedNamespace(ctx context.Context) (*Namespace, error) {
	state := e.identityStateSnapshot()

	namespaceIDRaw, err := protocol.RandomNamespaceID()
	if err != nil {
		return nil, err
	}
	namespaceDEK, err := protocol.RandomNamespaceDEK()
	if err != nil {
		return nil, err
	}
	namespaceID := hex.EncodeToString(namespaceIDRaw)
	wrappedDEK, err := wrapNamespaceDEKFor(namespaceID, namespaceDEK, e.identity.WrapPublicKey())
	if err != nil {
		return nil, err
	}

	resp, err := e.client.CreateSharedNamespace(ctx, state.AccessToken, protocol.CreateSharedNamespaceRequest{
		NamespaceID: namespaceID,
		WrappedDEK:  protocol.EncodeBase64(wrappedDEK),
	})
	if err != nil {
		return nil, err
	}

	if err := e.store.SaveNamespace(ctx, NamespaceState{
		KeyID:         e.keyID,
		NamespaceID:   resp.NamespaceID,
		Kind:          resp.Kind,
		NamespaceHead: 0,
		DEK:           bytes.Clone(namespaceDEK),
		UpdatedAt:     time.Now().UTC(),
	}); err != nil {
		return nil, err
	}
	return &Namespace{engine: e, namespaceID: resp.NamespaceID}, nil
}

// Namespace returns a handle for an already known namespace ID.
func (e *Engine) Namespace(ctx context.Context, namespaceID string) (*Namespace, error) {
	var namespace *Namespace
	if err := e.runAuthenticated(ctx, func() error {
		if _, err := e.ensureNamespaceReady(ctx, namespaceID, ""); err != nil {
			return err
		}
		namespace = &Namespace{engine: e, namespaceID: namespaceID}
		return nil
	}); err != nil {
		return nil, err
	}
	return namespace, nil
}

// JoinNamespace loads membership metadata and wrapped DEK for an existing
// namespace.
func (e *Engine) JoinNamespace(ctx context.Context, namespaceID string) (*Namespace, error) {
	var namespace *Namespace
	if err := e.runAuthenticated(ctx, func() error {
		if _, err := e.joinNamespace(ctx, namespaceID, ""); err != nil {
			return err
		}
		namespace = &Namespace{engine: e, namespaceID: namespaceID}
		return nil
	}); err != nil {
		return nil, err
	}
	return namespace, nil
}

// ListNamespaces refreshes and returns all namespaces visible to the current
// identity.
func (e *Engine) ListNamespaces(ctx context.Context) ([]NamespaceState, error) {
	var namespaces []NamespaceState
	if err := e.runAuthenticated(ctx, func() error {
		if err := e.syncNamespaces(ctx); err != nil {
			return err
		}
		var err error
		namespaces, err = e.store.ListNamespaces(ctx, e.keyID)
		return err
	}); err != nil {
		return nil, err
	}
	sort.Slice(namespaces, func(i, j int) bool {
		if namespaces[i].Kind == namespaces[j].Kind {
			return namespaces[i].NamespaceID < namespaces[j].NamespaceID
		}
		return namespaces[i].Kind < namespaces[j].Kind
	})
	return namespaces, nil
}

// syncNamespaces reconciles namespace membership, cached DEKs, and namespace
// heads with the server.
func (e *Engine) syncNamespaces(ctx context.Context) error {
	state := e.identityStateSnapshot()
	resp, err := e.client.ListNamespaces(ctx, state.AccessToken)
	if err != nil {
		return err
	}

	localNamespaces, err := e.store.ListNamespaces(ctx, e.keyID)
	if err != nil {
		return err
	}
	remoteNamespaceIDs := make(map[string]struct{}, len(resp.Namespaces))
	var remoteDefaultNamespaceID string
	for _, remoteNamespace := range resp.Namespaces {
		if err := validateNamespaceKind(remoteNamespace.Kind); err != nil {
			return err
		}
		if state.DefaultNamespaceID != "" &&
			remoteNamespace.NamespaceID == state.DefaultNamespaceID &&
			remoteNamespace.Kind != protocol.NamespaceKindDefault {
			return fmt.Errorf("%w for default namespace kind mismatch", ErrRollback)
		}
		remoteNamespaceIDs[remoteNamespace.NamespaceID] = struct{}{}
		if remoteNamespace.Kind == protocol.NamespaceKindDefault {
			if remoteDefaultNamespaceID != "" && remoteDefaultNamespaceID != remoteNamespace.NamespaceID {
				return fmt.Errorf("server returned multiple default namespaces")
			}
			remoteDefaultNamespaceID = remoteNamespace.NamespaceID
		}
	}
	if state.DefaultNamespaceID != "" && remoteDefaultNamespaceID != "" && state.DefaultNamespaceID != remoteDefaultNamespaceID {
		return fmt.Errorf("%w for default namespace mismatch", ErrRollback)
	}
	if state.DefaultNamespaceID != "" {
		if _, ok := remoteNamespaceIDs[state.DefaultNamespaceID]; !ok {
			return fmt.Errorf("%w for default namespace disappeared", ErrRollback)
		}
	}
	for _, localNamespace := range localNamespaces {
		if _, ok := remoteNamespaceIDs[localNamespace.NamespaceID]; !ok {
			return fmt.Errorf("%w for namespace %s disappeared", ErrRollback, localNamespace.NamespaceID)
		}
	}

	for _, remoteNamespace := range resp.Namespaces {
		localNamespace, err := e.getNamespaceState(ctx, remoteNamespace.NamespaceID)
		switch {
		case errors.Is(err, ErrNotFound):
			localNamespace = NamespaceState{
				KeyID:         e.keyID,
				NamespaceID:   remoteNamespace.NamespaceID,
				Kind:          remoteNamespace.Kind,
				NamespaceHead: 0,
			}
		case err != nil:
			return err
		}

		if remoteNamespace.NamespaceHead < localNamespace.NamespaceHead {
			return fmt.Errorf("%w for namespace %s", ErrRollback, remoteNamespace.NamespaceID)
		}
		localNamespace.Kind = remoteNamespace.Kind
		if len(localNamespace.DEK) == 0 {
			joinedNamespace, err := e.joinNamespace(ctx, remoteNamespace.NamespaceID, remoteNamespace.Kind)
			if err != nil {
				return err
			}
			localNamespace = joinedNamespace
		}
		remoteChanged := remoteNamespace.NamespaceHead > localNamespace.NamespaceHead
		scope, err := e.loadActiveScope(ctx, localNamespace)
		if err != nil {
			return err
		}
		scopeChanged := scope.activeScopeHash != localNamespace.ActiveScopeHash
		if remoteChanged || scopeChanged {
			if err := e.syncNamespaceItems(ctx, localNamespace, remoteNamespace.NamespaceHead, scope); err != nil {
				return err
			}
			localNamespace, err = e.getNamespaceState(ctx, remoteNamespace.NamespaceID)
			if err != nil {
				return err
			}
		} else {
			localNamespace.NamespaceHead = remoteNamespace.NamespaceHead
			localNamespace.ActiveScopeHash = scope.activeScopeHash
			localNamespace.UpdatedAt = time.Now().UTC()
			if err := e.store.SaveNamespace(ctx, localNamespace); err != nil {
				return err
			}
		}

		if remoteNamespace.Kind == protocol.NamespaceKindDefault && state.DefaultNamespaceID == "" {
			state.DefaultNamespaceID = remoteNamespace.NamespaceID
			state.UpdatedAt = time.Now().UTC()
			if err := e.saveIdentityState(ctx, state); err != nil {
				return err
			}
		}
	}
	return nil
}

// joinNamespace fetches and unwraps the namespace DEK for one namespace and
// caches the resulting namespace state.
func (e *Engine) joinNamespace(ctx context.Context, namespaceID, kindHint string) (NamespaceState, error) {
	state := e.identityStateSnapshot()
	wrappedResp, err := e.client.GetWrappedDEK(ctx, state.AccessToken, namespaceID, e.keyID)
	if err != nil {
		return NamespaceState{}, err
	}
	wrappedDEK, err := protocol.DecodeBase64("wrappedDek", wrappedResp.WrappedDEK)
	if err != nil {
		return NamespaceState{}, err
	}
	namespaceDEK, err := e.unwrapNamespaceDEK(ctx, namespaceID, wrappedDEK)
	if err != nil {
		return NamespaceState{}, err
	}

	namespaceState, err := e.getNamespaceState(ctx, namespaceID)
	if errors.Is(err, ErrNotFound) {
		namespaceState = NamespaceState{
			KeyID:       e.keyID,
			NamespaceID: namespaceID,
			Kind:        kindHint,
		}
	} else if err != nil {
		return NamespaceState{}, err
	}
	if namespaceState.Kind == "" {
		namespaceState.Kind = kindHint
	}
	namespaceState.DEK = bytes.Clone(namespaceDEK)
	namespaceState.UpdatedAt = time.Now().UTC()
	if err := e.store.SaveNamespace(ctx, namespaceState); err != nil {
		return NamespaceState{}, err
	}
	return namespaceState, nil
}

// ensureNamespaceReady ensures a namespace is cached locally with an available
// DEK and optional kind constraint.
func (e *Engine) ensureNamespaceReady(ctx context.Context, namespaceID, expectedKind string) (NamespaceState, error) {
	namespaceState, err := e.getNamespaceState(ctx, namespaceID)
	switch {
	case err == nil && len(namespaceState.DEK) > 0:
		if expectedKind != "" && namespaceState.Kind != expectedKind {
			return NamespaceState{}, fmt.Errorf("namespace %s has kind %s, expected %s", namespaceID, namespaceState.Kind, expectedKind)
		}
		return namespaceState, nil
	case err != nil && !errors.Is(err, ErrNotFound):
		return NamespaceState{}, err
	}

	if err := e.ensureAuthenticated(ctx); err != nil {
		return NamespaceState{}, err
	}
	namespaceState, err = e.joinNamespace(ctx, namespaceID, expectedKind)
	if err != nil {
		return NamespaceState{}, err
	}
	if expectedKind != "" && namespaceState.Kind != expectedKind {
		return NamespaceState{}, fmt.Errorf("namespace %s has kind %s, expected %s", namespaceID, namespaceState.Kind, expectedKind)
	}
	return namespaceState, nil
}

func validateNamespaceKind(kind string) error {
	switch kind {
	case protocol.NamespaceKindDefault, protocol.NamespaceKindShared:
		return nil
	default:
		return fmt.Errorf("unsupported namespace kind %q", kind)
	}
}

// getNamespaceState loads cached namespace state from the store.
func (e *Engine) getNamespaceState(ctx context.Context, namespaceID string) (NamespaceState, error) {
	state, err := e.store.GetNamespace(ctx, e.keyID, namespaceID)
	if err != nil {
		return NamespaceState{}, err
	}
	return state, nil
}
