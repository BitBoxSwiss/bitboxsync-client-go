// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"bitboxsync-client-go/protocol"
)

const (
	dummyAuthSeedInfo = "bitboxsync-auth-ed25519-seed-v1"
	dummyWrapSeedInfo = "bitboxsync-wrap-x25519-seed-v1"
)

// Identity abstracts the key operations that must be provided by a client,
// regardless of whether the underlying keys live in hardware or app-local
// secure storage. Public key accessors are used by the library for engine state
// and token serialization. Signing methods are action-specific so hardware
// implementations can build the canonical protocol payload internally and
// display a user-verifiable BitBoxSync action before approval.
type Identity interface {
	// Kind returns the auth-key kind represented by this identity, such as
	// "keystore".
	Kind() string
	// AuthPublicKey returns the Ed25519 public key corresponding to the typed
	// signing methods below.
	// Implementations should return a defensive copy when the key representation
	// is mutable.
	AuthPublicKey() ed25519.PublicKey
	// WrapPublicKey returns the X25519 public key used to wrap namespace DEKs
	// for this identity. Implementations must return the key corresponding to
	// the private key used by UnwrapNamespaceDEK.
	WrapPublicKey() *ecdh.PublicKey
	// SignLoginIntent signs the canonical login intent for challenge.
	// Hardware implementations must display that BitBoxSync login is being
	// approved.
	SignLoginIntent(ctx context.Context, challenge []byte) ([]byte, error)
	// SignRefreshIntent signs the canonical refresh intent for challenge.
	// Hardware implementations must display that BitBoxSync session refresh is
	// being approved.
	SignRefreshIntent(ctx context.Context, challenge []byte) ([]byte, error)
	// SignRevokeAllTokensIntent signs the canonical sensitive-action intent for
	// revoking all bearer tokens owned by this identity. Hardware
	// implementations must display that all BitBoxSync sessions are being
	// revoked.
	SignRevokeAllTokensIntent(ctx context.Context, challenge []byte) ([]byte, error)
	// SignCreateNamespaceInviteIntent signs the canonical sensitive-action
	// intent for namespace invite creation. Hardware implementations must
	// display the namespace fingerprint, invite fingerprint, expiry, and invite
	// limits being approved.
	SignCreateNamespaceInviteIntent(ctx context.Context, challenge, namespaceID, inviteID, inviteServerSecretHash []byte, expiresAt int64, maxPending, maxAccepted int) ([]byte, error)
	// SignNamespaceJoinRequestIntent signs the canonical join-request payload
	// for a scanned namespace invite. Hardware implementations must display the
	// server origin, namespace fingerprint, invite fingerprint, and expiry being
	// requested, and sign only the hash of that displayed canonical origin.
	SignNamespaceJoinRequestIntent(ctx context.Context, namespaceID, inviteID []byte, serverOrigin string, expiresAt int64) ([]byte, error)
	// Attest returns the identity's attestation proof for the supplied challenge.
	// Implementations that cannot attest should return an error.
	Attest(ctx context.Context, challenge []byte) ([]byte, error)
	// UnwrapNamespaceDEK unwraps a namespace DEK that was previously wrapped for
	// this identity. Implementations must reject wrapped payloads whose embedded
	// namespace binding does not match namespaceID.
	UnwrapNamespaceDEK(ctx context.Context, namespaceID []byte, wrappedDEK []byte) ([]byte, error)
}

// DummyKeystore is a deterministic software-only keystore-style Identity
// implementation used for demos and tests.
type DummyKeystore struct {
	authPriv ed25519.PrivateKey
	authPub  ed25519.PublicKey
	wrapPriv *ecdh.PrivateKey
	wrapPub  *ecdh.PublicKey
}

// NewDummyKeystore constructs a software-backed keystore Identity from a
// deterministic human-readable label.
func NewDummyKeystore(label string) (*DummyKeystore, error) {
	rootSecret := sha256.Sum256([]byte(label))

	authSeed, err := hkdf.Key(sha256.New, rootSecret[:], nil, dummyAuthSeedInfo, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("derive auth seed: %w", err)
	}
	authPriv := ed25519.NewKeyFromSeed(authSeed)
	authPub := authPriv.Public().(ed25519.PublicKey)

	wrapSeed, err := hkdf.Key(sha256.New, rootSecret[:], nil, dummyWrapSeedInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive wrap seed: %w", err)
	}
	wrapPriv, err := ecdh.X25519().NewPrivateKey(wrapSeed)
	if err != nil {
		return nil, fmt.Errorf("derive wrap private key: %w", err)
	}
	return &DummyKeystore{
		authPriv: authPriv,
		authPub:  authPub,
		wrapPriv: wrapPriv,
		wrapPub:  wrapPriv.PublicKey(),
	}, nil
}

// Kind returns the auth-key kind of the dummy keystore identity.
func (d *DummyKeystore) Kind() string {
	return protocol.IdentityKindKeystore
}

// AuthPublicKey returns the authentication public key.
func (d *DummyKeystore) AuthPublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), d.authPub...)
}

// WrapPublicKey returns the public key used for namespace DEK wrapping.
func (d *DummyKeystore) WrapPublicKey() *ecdh.PublicKey {
	return d.wrapPub
}

func (d *DummyKeystore) keyID() [protocol.KeyIDLength]byte {
	return protocol.KeyIDFromAuthPublicKey(d.authPub)
}

func (d *DummyKeystore) signPayload(payload []byte) []byte {
	return ed25519.Sign(d.authPriv, payload)
}

// SignLoginIntent signs the canonical login intent for the dummy keystore.
func (d *DummyKeystore) SignLoginIntent(_ context.Context, challenge []byte) ([]byte, error) {
	keyID := d.keyID()
	payload, err := protocol.LoginIntent(challenge, d.Kind(), keyID[:], d.authPub, d.wrapPub)
	if err != nil {
		return nil, err
	}
	return d.signPayload(payload), nil
}

// SignRefreshIntent signs the canonical refresh intent for the dummy keystore.
func (d *DummyKeystore) SignRefreshIntent(_ context.Context, challenge []byte) ([]byte, error) {
	keyID := d.keyID()
	payload, err := protocol.RefreshIntent(challenge, d.Kind(), keyID[:])
	if err != nil {
		return nil, err
	}
	return d.signPayload(payload), nil
}

// SignRevokeAllTokensIntent signs the canonical revoke-all-tokens intent for
// the dummy keystore.
func (d *DummyKeystore) SignRevokeAllTokensIntent(_ context.Context, challenge []byte) ([]byte, error) {
	keyID := d.keyID()
	payload, err := protocol.SensitiveActionIntent(
		challenge,
		protocol.SensitiveActionRevokeAllTokens,
		d.Kind(),
		keyID[:],
		nil,
	)
	if err != nil {
		return nil, err
	}
	return d.signPayload(payload), nil
}

// SignCreateNamespaceInviteIntent signs the namespace-invite sensitive action
// for the dummy keystore.
func (d *DummyKeystore) SignCreateNamespaceInviteIntent(_ context.Context, challenge, namespaceID, inviteID, inviteServerSecretHash []byte, expiresAt int64, maxPending, maxAccepted int) ([]byte, error) {
	if expiresAt < 0 {
		return nil, fmt.Errorf("namespace invite expiry before unix epoch")
	}
	if maxPending < 0 || maxAccepted < 0 ||
		maxPending > protocol.MaxPendingJoinRequestsPerInvite ||
		maxAccepted > protocol.MaxAcceptedJoinRequestsPerInvite {
		return nil, fmt.Errorf("namespace invite limits are out of range")
	}
	keyID := d.keyID()
	actionFields, err := protocol.CreateNamespaceInviteActionFields(
		namespaceID,
		inviteID,
		inviteServerSecretHash,
		uint64(expiresAt),
		uint32(maxPending),
		uint32(maxAccepted),
	)
	if err != nil {
		return nil, err
	}
	payload, err := protocol.SensitiveActionIntent(
		challenge,
		protocol.SensitiveActionCreateNamespaceInvite,
		d.Kind(),
		keyID[:],
		actionFields,
	)
	if err != nil {
		return nil, err
	}
	return d.signPayload(payload), nil
}

// SignNamespaceJoinRequestIntent signs a namespace join request for the dummy
// keystore.
func (d *DummyKeystore) SignNamespaceJoinRequestIntent(_ context.Context, namespaceID, inviteID []byte, serverOrigin string, expiresAt int64) ([]byte, error) {
	if expiresAt < 0 {
		return nil, fmt.Errorf("join request expiry before unix epoch")
	}
	serverOriginHash, err := protocol.ServerOriginHash(serverOrigin)
	if err != nil {
		return nil, err
	}
	keyID := d.keyID()
	payload, err := protocol.JoinRequestPayload(d.Kind(), namespaceID, inviteID, serverOriginHash, keyID[:], d.authPub, d.wrapPub, uint64(expiresAt))
	if err != nil {
		return nil, err
	}
	return d.signPayload(payload), nil
}

// Attest returns the demo attestation payload for the dummy keystore.
func (d *DummyKeystore) Attest(_ context.Context, challenge []byte) ([]byte, error) {
	out := make([]byte, 257)
	out[0] = 0x00
	material := sha256.Sum256(append(append([]byte(nil), challenge...), d.authPub...))
	offset := 1
	current := material[:]
	for offset < len(out) {
		sum := sha256.Sum256(current)
		offset += copy(out[offset:], sum[:])
		current = sum[:]
	}
	return out, nil
}

// UnwrapNamespaceDEK unwraps a namespace DEK that was wrapped for this
// keystore identity.
func (d *DummyKeystore) UnwrapNamespaceDEK(_ context.Context, namespaceID []byte, wrappedDEK []byte) ([]byte, error) {
	return protocol.UnwrapNamespaceDEK(d.wrapPriv.Bytes(), namespaceID, wrappedDEK)
}
