// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"bitboxsync-client-go/protocol"
	"bitboxsync-client-go/raw"
	"github.com/stretchr/testify/require"
)

func TestOpenDerivesKeyIDFromIdentityAuthPublicKey(t *testing.T) {
	ctx := context.Background()
	identity := newRecordingIdentity(t)
	client, err := raw.New("http://127.0.0.1:1", nil)
	require.NoError(t, err)
	engine, err := Open(ctx, Config{
		Client:   client,
		Identity: identity,
		Store:    newTestStore(),
	})
	require.NoError(t, err)
	defer closeTestEngine(t, engine)

	wantRaw := protocol.KeyIDFromAuthPublicKey(identity.AuthPublicKey())
	want := hex.EncodeToString(wantRaw[:])
	require.Equal(t, want, engine.KeyID())
	require.Equal(t, wantRaw, engine.keyIDRaw)
	require.Equal(t, identity.Kind(), engine.Identity().Kind)
}

func TestIdentityIntentHelpersUseTypedIntentMethods(t *testing.T) {
	ctx := context.Background()
	identity := newRecordingIdentity(t)
	keyIDRaw := protocol.KeyIDFromAuthPublicKey(identity.AuthPublicKey())
	engine := &Engine{
		keyID:    hex.EncodeToString(keyIDRaw[:]),
		keyIDRaw: keyIDRaw,
		identity: identity,
	}

	loginChallenge := bytes.Repeat([]byte{0x01}, 32)
	loginSignature, err := engine.signLoginIntent(ctx, loginChallenge)
	require.NoError(t, err)
	wantLogin, err := protocol.LoginIntent(
		loginChallenge,
		identity.Kind(),
		keyIDRaw[:],
		identity.AuthPublicKey(),
		identity.WrapPublicKey(),
	)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(identity.authPub, wantLogin, loginSignature))
	assertIdentityCall(t, identity, 0, identityCall{name: "login", challenge: loginChallenge})

	refreshChallenge := bytes.Repeat([]byte{0x02}, 32)
	refreshSignature, err := engine.signRefreshIntent(ctx, refreshChallenge)
	require.NoError(t, err)
	wantRefresh, err := protocol.RefreshIntent(refreshChallenge, identity.Kind(), keyIDRaw[:])
	require.NoError(t, err)
	require.True(t, ed25519.Verify(identity.authPub, wantRefresh, refreshSignature))
	assertIdentityCall(t, identity, 1, identityCall{name: "refresh", challenge: refreshChallenge})

	revokeChallenge := bytes.Repeat([]byte{0x03}, 32)
	revokeSignature, err := engine.signRevokeAllTokensIntent(ctx, revokeChallenge)
	require.NoError(t, err)
	wantRevoke, err := protocol.SensitiveActionIntent(
		revokeChallenge,
		protocol.SensitiveActionRevokeAllTokens,
		identity.Kind(),
		keyIDRaw[:],
		nil,
	)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(identity.authPub, wantRevoke, revokeSignature))
	assertIdentityCall(t, identity, 2, identityCall{name: "revoke", challenge: revokeChallenge})

	namespaceID := bytes.Repeat([]byte{0x04}, protocol.NamespaceIDLength)
	inviteID := bytes.Repeat([]byte{0x05}, protocol.InviteIDLength)
	inviteSecretHash := bytes.Repeat([]byte{0x06}, protocol.InviteServerSecretHashLength)
	createChallenge := bytes.Repeat([]byte{0x07}, 32)
	createSignature, err := engine.signCreateNamespaceInviteIntent(ctx, createChallenge, namespaceID, inviteID, inviteSecretHash, 1234, 2, 3)
	require.NoError(t, err)
	actionFields, err := protocol.CreateNamespaceInviteActionFields(namespaceID, inviteID, inviteSecretHash, 1234, 2, 3)
	require.NoError(t, err)
	wantCreate, err := protocol.SensitiveActionIntent(
		createChallenge,
		protocol.SensitiveActionCreateNamespaceInvite,
		identity.Kind(),
		keyIDRaw[:],
		actionFields,
	)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(identity.authPub, wantCreate, createSignature))
	assertIdentityCall(t, identity, 3, identityCall{
		name:                   "create-invite",
		challenge:              createChallenge,
		namespaceID:            namespaceID,
		inviteID:               inviteID,
		inviteServerSecretHash: inviteSecretHash,
		expiresAt:              1234,
		maxPending:             2,
		maxAccepted:            3,
	})

	serverOrigin := "https://sync.example"
	serverOriginHash := sha256.Sum256([]byte(serverOrigin))
	joinSignature, err := engine.signNamespaceJoinRequestIntent(ctx, namespaceID, inviteID, serverOrigin, 2345)
	require.NoError(t, err)
	wantJoin, err := protocol.JoinRequestPayload(identity.Kind(), namespaceID, inviteID, serverOriginHash[:], keyIDRaw[:], identity.AuthPublicKey(), identity.WrapPublicKey(), 2345)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(identity.authPub, wantJoin, joinSignature))
	assertIdentityCall(t, identity, 4, identityCall{
		name:         "join-request",
		namespaceID:  namespaceID,
		inviteID:     inviteID,
		serverOrigin: serverOrigin,
		expiresAt:    2345,
	})
}

func assertIdentityCall(t *testing.T, identity *recordingIdentity, index int, want identityCall) {
	t.Helper()

	require.Greater(t, len(identity.calls), index)
	require.Equal(t, want, identity.calls[index])
}

type identityCall struct {
	name                   string
	challenge              []byte
	namespaceID            []byte
	inviteID               []byte
	inviteServerSecretHash []byte
	serverOrigin           string
	expiresAt              int64
	maxPending             int
	maxAccepted            int
}

type recordingIdentity struct {
	authPriv ed25519.PrivateKey
	authPub  ed25519.PublicKey
	wrapPriv *ecdh.PrivateKey
	wrapPub  *ecdh.PublicKey
	calls    []identityCall
}

var _ raw.Identity = (*recordingIdentity)(nil)

func newRecordingIdentity(t *testing.T) *recordingIdentity {
	t.Helper()

	authPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	authPub := authPriv.Public().(ed25519.PublicKey)
	wrapPriv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x24}, 32))
	require.NoError(t, err)
	return &recordingIdentity{
		authPriv: authPriv,
		authPub:  authPub,
		wrapPriv: wrapPriv,
		wrapPub:  wrapPriv.PublicKey(),
	}
}

func (r *recordingIdentity) Kind() string {
	return protocol.IdentityKindKeystore
}

func (r *recordingIdentity) AuthPublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), r.authPub...)
}

func (r *recordingIdentity) WrapPublicKey() *ecdh.PublicKey {
	return r.wrapPub
}

func (r *recordingIdentity) keyID() [protocol.KeyIDLength]byte {
	return protocol.KeyIDFromAuthPublicKey(r.authPub)
}

func (r *recordingIdentity) SignLoginIntent(_ context.Context, challenge []byte) ([]byte, error) {
	r.calls = append(r.calls, identityCall{name: "login", challenge: bytes.Clone(challenge)})
	keyID := r.keyID()
	payload, err := protocol.LoginIntent(challenge, r.Kind(), keyID[:], r.authPub, r.wrapPub)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(r.authPriv, payload), nil
}

func (r *recordingIdentity) SignRefreshIntent(_ context.Context, challenge []byte) ([]byte, error) {
	r.calls = append(r.calls, identityCall{name: "refresh", challenge: bytes.Clone(challenge)})
	keyID := r.keyID()
	payload, err := protocol.RefreshIntent(challenge, r.Kind(), keyID[:])
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(r.authPriv, payload), nil
}

func (r *recordingIdentity) SignRevokeAllTokensIntent(_ context.Context, challenge []byte) ([]byte, error) {
	r.calls = append(r.calls, identityCall{name: "revoke", challenge: bytes.Clone(challenge)})
	keyID := r.keyID()
	payload, err := protocol.SensitiveActionIntent(
		challenge,
		protocol.SensitiveActionRevokeAllTokens,
		r.Kind(),
		keyID[:],
		nil,
	)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(r.authPriv, payload), nil
}

func (r *recordingIdentity) SignCreateNamespaceInviteIntent(_ context.Context, challenge, namespaceID, inviteID, inviteServerSecretHash []byte, expiresAt int64, maxPending, maxAccepted int) ([]byte, error) {
	r.calls = append(r.calls, identityCall{
		name:                   "create-invite",
		challenge:              bytes.Clone(challenge),
		namespaceID:            bytes.Clone(namespaceID),
		inviteID:               bytes.Clone(inviteID),
		inviteServerSecretHash: bytes.Clone(inviteServerSecretHash),
		expiresAt:              expiresAt,
		maxPending:             maxPending,
		maxAccepted:            maxAccepted,
	})
	keyID := r.keyID()
	actionFields, err := protocol.CreateNamespaceInviteActionFields(namespaceID, inviteID, inviteServerSecretHash, uint64(expiresAt), uint32(maxPending), uint32(maxAccepted))
	if err != nil {
		return nil, err
	}
	payload, err := protocol.SensitiveActionIntent(
		challenge,
		protocol.SensitiveActionCreateNamespaceInvite,
		r.Kind(),
		keyID[:],
		actionFields,
	)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(r.authPriv, payload), nil
}

func (r *recordingIdentity) SignNamespaceJoinRequestIntent(_ context.Context, namespaceID, inviteID []byte, serverOrigin string, expiresAt int64) ([]byte, error) {
	r.calls = append(r.calls, identityCall{
		name:         "join-request",
		namespaceID:  bytes.Clone(namespaceID),
		inviteID:     bytes.Clone(inviteID),
		serverOrigin: serverOrigin,
		expiresAt:    expiresAt,
	})
	keyID := r.keyID()
	serverOriginHash, err := protocol.ServerOriginHash(serverOrigin)
	if err != nil {
		return nil, err
	}
	payload, err := protocol.JoinRequestPayload(r.Kind(), namespaceID, inviteID, serverOriginHash, keyID[:], r.authPub, r.wrapPub, uint64(expiresAt))
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(r.authPriv, payload), nil
}

func (r *recordingIdentity) Attest(_ context.Context, challenge []byte) ([]byte, error) {
	return append([]byte(nil), challenge...), nil
}

func (r *recordingIdentity) UnwrapNamespaceDEK(_ context.Context, namespaceID []byte, wrappedDEK []byte) ([]byte, error) {
	return protocol.UnwrapNamespaceDEK(r.wrapPriv.Bytes(), namespaceID, wrappedDEK)
}
