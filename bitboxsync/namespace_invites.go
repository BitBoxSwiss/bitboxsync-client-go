// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"bitboxsync-client-go/protocol"
)

const maxStoredInviteLimit = int64(1<<31 - 1)

func checkedUint32(name string, value int) (uint32, error) {
	if value <= 0 || int64(value) > maxStoredInviteLimit {
		return 0, fmt.Errorf("%s is out of range", name)
	}
	return uint32(value), nil
}

// CreateInvite creates a short-lived namespace invite and returns the QR
// material that prospective members can scan.
func (n *Namespace) CreateInvite(ctx context.Context, opts NamespaceInviteOptions) (protocol.NamespaceInviteToken, error) {
	if opts.TTL <= 0 {
		opts.TTL = n.engine.cfg.InviteTTL
	}
	if opts.TTL > protocol.MaxInviteTTL {
		return protocol.NamespaceInviteToken{}, fmt.Errorf("invite ttl exceeds maximum %s", protocol.MaxInviteTTL)
	}
	if opts.MaxPending <= 0 {
		opts.MaxPending = protocol.MaxPendingJoinRequestsPerInvite
	}
	if opts.MaxAccepted <= 0 {
		opts.MaxAccepted = protocol.MaxAcceptedJoinRequestsPerInvite
	}
	if opts.MaxPending > protocol.MaxPendingJoinRequestsPerInvite {
		return protocol.NamespaceInviteToken{}, fmt.Errorf("maxPending exceeds maximum %d", protocol.MaxPendingJoinRequestsPerInvite)
	}
	if opts.MaxAccepted > protocol.MaxAcceptedJoinRequestsPerInvite {
		return protocol.NamespaceInviteToken{}, fmt.Errorf("maxAccepted exceeds maximum %d", protocol.MaxAcceptedJoinRequestsPerInvite)
	}
	serverOrigin, err := protocol.CanonicalServerOrigin(opts.ServerOrigin)
	if err != nil {
		return protocol.NamespaceInviteToken{}, err
	}
	namespaceIDRaw, err := protocol.DecodeLowerHexExact("namespaceId", n.namespaceID, protocol.NamespaceIDLength)
	if err != nil {
		return protocol.NamespaceInviteToken{}, err
	}
	if _, err := n.engine.ensureNamespaceReady(ctx, n.namespaceID, protocol.NamespaceKindShared); err != nil {
		return protocol.NamespaceInviteToken{}, err
	}
	var inviteIDRaw []byte
	if opts.InviteID != "" {
		inviteIDRaw, err = protocol.DecodeLowerHexExact("inviteId", opts.InviteID, protocol.InviteIDLength)
		if err != nil {
			return protocol.NamespaceInviteToken{}, err
		}
	} else {
		inviteIDRaw, err = protocol.RandomInviteID()
		if err != nil {
			return protocol.NamespaceInviteToken{}, err
		}
	}
	var inviteSecret []byte
	if opts.InviteSecret != "" {
		inviteSecret, err = protocol.DecodeBase64URLExact("inviteSecret", opts.InviteSecret, protocol.InviteSecretLength)
		if err != nil {
			return protocol.NamespaceInviteToken{}, err
		}
	} else {
		inviteSecret, err = protocol.RandomInviteSecret()
		if err != nil {
			return protocol.NamespaceInviteToken{}, err
		}
	}
	maxPending, err := checkedUint32("maxPending", opts.MaxPending)
	if err != nil {
		return protocol.NamespaceInviteToken{}, err
	}
	maxAccepted, err := checkedUint32("maxAccepted", opts.MaxAccepted)
	if err != nil {
		return protocol.NamespaceInviteToken{}, err
	}
	expiresAt := time.Now().UTC().Add(opts.TTL).Unix()
	if expiresAt < 0 {
		return protocol.NamespaceInviteToken{}, fmt.Errorf("invite expiry must be non-negative")
	}
	token := protocol.NamespaceInviteToken{
		Version:      protocol.NamespaceJoinRequestVersion,
		ServerOrigin: serverOrigin,
		NamespaceID:  n.namespaceID,
		InviteID:     hex.EncodeToString(inviteIDRaw),
		ExpiresAt:    expiresAt,
		InviteSecret: protocol.EncodeBase64URL(inviteSecret),
	}
	inviteServerSecret, err := protocol.DeriveInviteServerSecret(inviteSecret)
	if err != nil {
		return protocol.NamespaceInviteToken{}, err
	}
	inviteServerSecretHash := sha256.Sum256(inviteServerSecret)
	actionFields, err := protocol.CreateNamespaceInviteActionFields(
		namespaceIDRaw,
		inviteIDRaw,
		inviteServerSecretHash[:],
		uint64(expiresAt),
		maxPending,
		maxAccepted,
	)
	if err != nil {
		return protocol.NamespaceInviteToken{}, err
	}
	actionFieldsHash := sha256.Sum256(actionFields)

	if err := n.engine.runAuthenticated(ctx, func() error {
		state := n.engine.identityStateSnapshot()
		challengeResp, err := n.engine.client.SensitiveActionChallenge(
			ctx,
			protocol.SensitiveActionCreateNamespaceInvite,
			hex.EncodeToString(actionFieldsHash[:]),
		)
		if err != nil {
			return err
		}
		if challengeResp.SpamControl.Kind != protocol.SpamControlKindNone {
			return fmt.Errorf("unsupported spam control kind %q for namespace invite creation", challengeResp.SpamControl.Kind)
		}
		challenge, err := protocol.DecodeBase64Exact("challenge", challengeResp.Challenge, 32)
		if err != nil {
			return err
		}
		signature, err := n.engine.signCreateNamespaceInviteIntent(
			ctx,
			challenge,
			namespaceIDRaw,
			inviteIDRaw,
			inviteServerSecretHash[:],
			expiresAt,
			opts.MaxPending,
			opts.MaxAccepted,
		)
		if err != nil {
			return err
		}
		resp, err := n.engine.client.CreateNamespaceInvite(ctx, state.AccessToken, n.namespaceID, protocol.CreateNamespaceInviteRequest{
			Kind:                   n.engine.identity.Kind(),
			KeyID:                  n.engine.keyID,
			InviteID:               token.InviteID,
			InviteServerSecretHash: hex.EncodeToString(inviteServerSecretHash[:]),
			Challenge:              challengeResp.Challenge,
			IntentSignature:        hex.EncodeToString(signature),
			ExpiresAt:              expiresAt,
			MaxPending:             opts.MaxPending,
			MaxAccepted:            opts.MaxAccepted,
		})
		if err != nil {
			return err
		}
		if resp.ExpiresAt != expiresAt {
			return fmt.Errorf("create invite response expiry mismatch: got %d want %d", resp.ExpiresAt, expiresAt)
		}
		if resp.MaxPending != opts.MaxPending {
			return fmt.Errorf("create invite response maxPending mismatch: got %d want %d", resp.MaxPending, opts.MaxPending)
		}
		if resp.MaxAccepted != opts.MaxAccepted {
			return fmt.Errorf("create invite response maxAccepted mismatch: got %d want %d", resp.MaxAccepted, opts.MaxAccepted)
		}
		token.NamespaceID = resp.NamespaceID
		token.InviteID = resp.InviteID
		return nil
	}); err != nil {
		return token, err
	}
	return token, nil
}

// InviteURI encodes a namespace invite token as the QR/copy URI.
func InviteURI(token protocol.NamespaceInviteToken) (string, error) {
	return protocol.EncodeNamespaceInviteToken(token)
}

// ParseInviteURI parses a QR/copy namespace invite URI.
func ParseInviteURI(value string) (protocol.NamespaceInviteToken, error) {
	return protocol.ParseNamespaceInviteToken(value)
}

// SubmitJoinRequest signs and submits a request to join the namespace named by
// invite.
func (e *Engine) SubmitJoinRequest(ctx context.Context, invite protocol.NamespaceInviteToken, opts NamespaceJoinRequestOptions) (*protocol.SubmitNamespaceJoinRequestResponse, error) {
	if invite.Version != protocol.NamespaceJoinRequestVersion {
		return nil, protocol.ErrUnsupportedVersion
	}
	if invite.ExpiresAt <= 0 {
		return nil, fmt.Errorf("invite expiry must be positive")
	}
	if opts.TTL <= 0 || opts.TTL > protocol.MaxJoinRequestTTL {
		opts.TTL = protocol.MaxJoinRequestTTL
	}
	serverOrigin, err := protocol.CanonicalServerOrigin(invite.ServerOrigin)
	if err != nil {
		return nil, err
	}
	if serverOrigin != invite.ServerOrigin {
		return nil, fmt.Errorf("invite server origin must be canonical")
	}
	namespaceIDRaw, err := protocol.DecodeLowerHexExact("namespaceId", invite.NamespaceID, protocol.NamespaceIDLength)
	if err != nil {
		return nil, err
	}
	inviteIDRaw, err := protocol.DecodeLowerHexExact("inviteId", invite.InviteID, protocol.InviteIDLength)
	if err != nil {
		return nil, err
	}
	inviteSecret, err := protocol.DecodeBase64URLExact("inviteSecret", invite.InviteSecret, protocol.InviteSecretLength)
	if err != nil {
		return nil, err
	}
	inviteServerSecret, err := protocol.DeriveInviteServerSecret(inviteSecret)
	if err != nil {
		return nil, err
	}
	serverOriginHash, err := protocol.ServerOriginHash(serverOrigin)
	if err != nil {
		return nil, err
	}
	expiresAt := opts.ExpiresAt
	now := time.Now().UTC()
	if expiresAt == 0 {
		expiresAt = now.Add(opts.TTL).Unix()
		if expiresAt > invite.ExpiresAt {
			expiresAt = invite.ExpiresAt
		}
	}
	if expiresAt < 0 {
		return nil, fmt.Errorf("join request expiry must be non-negative")
	}
	if expiresAt > now.Add(protocol.MaxJoinRequestTTL).Unix() {
		return nil, fmt.Errorf("join request expiry exceeds maximum %s", protocol.MaxJoinRequestTTL)
	}
	if expiresAt > invite.ExpiresAt {
		return nil, fmt.Errorf("join request expires after invite")
	}
	if expiresAt <= now.Unix() {
		return nil, fmt.Errorf("invite has expired")
	}
	authPublicKey := e.identity.AuthPublicKey()
	wrapPublicKey := e.identity.WrapPublicKey()
	signature, err := e.signNamespaceJoinRequestIntent(ctx, namespaceIDRaw, inviteIDRaw, serverOrigin, expiresAt)
	if err != nil {
		return nil, err
	}
	payload, err := protocol.JoinRequestPayload(
		e.identity.Kind(),
		namespaceIDRaw,
		inviteIDRaw,
		serverOriginHash,
		e.keyIDRaw[:],
		authPublicKey,
		wrapPublicKey,
		uint64(expiresAt),
	)
	if err != nil {
		return nil, err
	}
	inviteProof, err := protocol.InviteProof(inviteSecret, payload)
	if err != nil {
		return nil, err
	}

	joinRequest := protocol.NamespaceJoinRequest{
		Version:       protocol.NamespaceJoinRequestVersion,
		NamespaceID:   invite.NamespaceID,
		InviteID:      invite.InviteID,
		ServerOrigin:  serverOrigin,
		Kind:          e.identity.Kind(),
		KeyID:         e.keyID,
		AuthPublicKey: protocol.EncodeEd25519PublicKey(authPublicKey),
		WrapPublicKey: protocol.EncodeX25519PublicKey(wrapPublicKey),
		ExpiresAt:     expiresAt,
		Signature:     hex.EncodeToString(signature),
		InviteProof:   protocol.EncodeBase64URL(inviteProof),
	}
	var resp *protocol.SubmitNamespaceJoinRequestResponse
	if err := e.runAuthenticated(ctx, func() error {
		state := e.identityStateSnapshot()
		var err error
		resp, err = e.client.SubmitNamespaceJoinRequest(ctx, state.AccessToken, invite.NamespaceID, invite.InviteID, protocol.SubmitNamespaceJoinRequestRequest{
			InviteServerSecret: protocol.EncodeBase64URL(inviteServerSecret),
			JoinRequest:        joinRequest,
		})
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// JoinRequests lists active pending join requests for this namespace.
func (n *Namespace) JoinRequests(ctx context.Context) ([]protocol.NamespaceJoinRequestEntry, error) {
	var requests []protocol.NamespaceJoinRequestEntry
	if err := n.engine.runAuthenticated(ctx, func() error {
		state := n.engine.identityStateSnapshot()
		resp, err := n.engine.client.ListNamespaceJoinRequests(ctx, state.AccessToken, n.namespaceID)
		if err != nil {
			return err
		}
		requests = resp.Requests
		return nil
	}); err != nil {
		return nil, err
	}
	return requests, nil
}

// ApproveJoinRequest verifies a pending join request against invite, wraps this
// namespace's DEK for the requester, and approves the request.
func (n *Namespace) ApproveJoinRequest(ctx context.Context, invite protocol.NamespaceInviteToken, entry protocol.NamespaceJoinRequestEntry) error {
	recipientWrapPublicKey, inviteServerSecret, joinRequestHash, err := verifyJoinRequestForApproval(n.namespaceID, invite, entry, time.Now().UTC())
	if err != nil {
		return err
	}
	namespaceState, err := n.engine.ensureNamespaceReady(ctx, n.namespaceID, protocol.NamespaceKindShared)
	if err != nil {
		return err
	}
	wrappedDEK, err := wrapNamespaceDEKFor(n.namespaceID, namespaceState.DEK, recipientWrapPublicKey)
	if err != nil {
		return err
	}
	return n.engine.runAuthenticated(ctx, func() error {
		state := n.engine.identityStateSnapshot()
		_, err := n.engine.client.ApproveNamespaceJoinRequest(ctx, state.AccessToken, n.namespaceID, entry.JoinRequest.KeyID, joinRequestHash, protocol.ApproveNamespaceJoinRequestRequest{
			InviteServerSecret: protocol.EncodeBase64URL(inviteServerSecret),
			WrappedDEK:         protocol.EncodeBase64(wrappedDEK),
		})
		return err
	})
}

// RejectJoinRequest rejects one pending request for this namespace.
func (n *Namespace) RejectJoinRequest(ctx context.Context, entry protocol.NamespaceJoinRequestEntry) error {
	return n.engine.runAuthenticated(ctx, func() error {
		state := n.engine.identityStateSnapshot()
		_, err := n.engine.client.RejectNamespaceJoinRequest(ctx, state.AccessToken, n.namespaceID, entry.JoinRequest.KeyID, entry.JoinRequestHash)
		return err
	})
}

// RevokeInvite revokes one namespace invite.
func (n *Namespace) RevokeInvite(ctx context.Context, inviteID string) error {
	return n.engine.runAuthenticated(ctx, func() error {
		state := n.engine.identityStateSnapshot()
		_, err := n.engine.client.RevokeNamespaceInvite(ctx, state.AccessToken, n.namespaceID, inviteID)
		return err
	})
}

// Invites lists namespace invite management metadata visible to this member.
func (n *Namespace) Invites(ctx context.Context) ([]protocol.NamespaceInviteSummary, error) {
	var invites []protocol.NamespaceInviteSummary
	if err := n.engine.runAuthenticated(ctx, func() error {
		state := n.engine.identityStateSnapshot()
		resp, err := n.engine.client.ListNamespaceInvites(ctx, state.AccessToken, n.namespaceID)
		if err != nil {
			return err
		}
		invites = resp.Invites
		return nil
	}); err != nil {
		return nil, err
	}
	return invites, nil
}

type parsedNamespaceJoinRequest struct {
	payload       []byte
	hash          string
	signature     []byte
	inviteProof   []byte
	authPublicKey ed25519.PublicKey
	wrapPublicKey *ecdh.PublicKey
}

func parseNamespaceJoinRequest(joinRequest protocol.NamespaceJoinRequest) (*parsedNamespaceJoinRequest, error) {
	if joinRequest.Version != protocol.NamespaceJoinRequestVersion {
		return nil, protocol.ErrUnsupportedVersion
	}
	if joinRequest.Kind != protocol.IdentityKindKeystore {
		return nil, protocol.ErrInvalidKind
	}
	if joinRequest.ExpiresAt < 0 {
		return nil, fmt.Errorf("join request expiry must be non-negative")
	}
	namespaceIDRaw, err := protocol.DecodeLowerHexExact("joinRequest.namespaceId", joinRequest.NamespaceID, protocol.NamespaceIDLength)
	if err != nil {
		return nil, err
	}
	inviteIDRaw, err := protocol.DecodeLowerHexExact("joinRequest.inviteId", joinRequest.InviteID, protocol.InviteIDLength)
	if err != nil {
		return nil, err
	}
	serverOriginHash, err := protocol.ServerOriginHash(joinRequest.ServerOrigin)
	if err != nil {
		return nil, err
	}
	keyID, err := protocol.DecodeLowerHexExact("joinRequest.keyId", joinRequest.KeyID, protocol.KeyIDLength)
	if err != nil {
		return nil, err
	}
	authPublicKey, err := protocol.ParseEd25519PublicKeyHex("joinRequest.authPublicKey", joinRequest.AuthPublicKey)
	if err != nil {
		return nil, err
	}
	wrapPublicKey, err := protocol.ParseX25519PublicKeyHex("joinRequest.wrapPublicKey", joinRequest.WrapPublicKey)
	if err != nil {
		return nil, err
	}
	signature, err := protocol.DecodeLowerHexExact("joinRequest.signature", joinRequest.Signature, ed25519.SignatureSize)
	if err != nil {
		return nil, err
	}
	inviteProof, err := protocol.DecodeBase64URLExact("joinRequest.inviteProof", joinRequest.InviteProof, protocol.InviteProofLength)
	if err != nil {
		return nil, err
	}
	if err := protocol.VerifyKeyIDMatchesAuthPublicKey(joinRequest.KeyID, authPublicKey); err != nil {
		return nil, err
	}
	payload, err := protocol.JoinRequestPayload(joinRequest.Kind, namespaceIDRaw, inviteIDRaw, serverOriginHash, keyID, authPublicKey, wrapPublicKey, uint64(joinRequest.ExpiresAt))
	if err != nil {
		return nil, err
	}
	return &parsedNamespaceJoinRequest{
		payload:       payload,
		hash:          hex.EncodeToString(protocol.JoinRequestHash(payload)),
		signature:     signature,
		inviteProof:   inviteProof,
		authPublicKey: authPublicKey,
		wrapPublicKey: wrapPublicKey,
	}, nil
}

func verifyJoinRequestForApproval(namespaceID string, invite protocol.NamespaceInviteToken, entry protocol.NamespaceJoinRequestEntry, now time.Time) (*ecdh.PublicKey, []byte, string, error) {
	joinRequest := entry.JoinRequest
	if invite.Version != protocol.NamespaceJoinRequestVersion {
		return nil, nil, "", protocol.ErrUnsupportedVersion
	}
	if invite.ExpiresAt <= 0 {
		return nil, nil, "", fmt.Errorf("invite expiry must be positive")
	}
	if invite.ExpiresAt <= now.Unix() {
		return nil, nil, "", fmt.Errorf("invite has expired")
	}
	if invite.NamespaceID != namespaceID || joinRequest.NamespaceID != namespaceID {
		return nil, nil, "", fmt.Errorf("join request namespace mismatch")
	}
	if joinRequest.InviteID != invite.InviteID {
		return nil, nil, "", fmt.Errorf("join request invite mismatch")
	}
	serverOrigin, err := protocol.CanonicalServerOrigin(invite.ServerOrigin)
	if err != nil {
		return nil, nil, "", err
	}
	if serverOrigin != invite.ServerOrigin {
		return nil, nil, "", fmt.Errorf("invite server origin must be canonical")
	}
	if joinRequest.ServerOrigin != serverOrigin {
		return nil, nil, "", fmt.Errorf("join request server origin mismatch")
	}
	if joinRequest.Version != protocol.NamespaceJoinRequestVersion {
		return nil, nil, "", protocol.ErrUnsupportedVersion
	}
	if joinRequest.Kind != protocol.IdentityKindKeystore {
		return nil, nil, "", protocol.ErrInvalidKind
	}
	if joinRequest.ExpiresAt <= now.Unix() {
		return nil, nil, "", fmt.Errorf("join request has expired")
	}
	if joinRequest.ExpiresAt > invite.ExpiresAt {
		return nil, nil, "", fmt.Errorf("join request expires after invite")
	}
	parsedJoinRequest, err := parseNamespaceJoinRequest(joinRequest)
	if err != nil {
		return nil, nil, "", err
	}
	if entry.JoinRequestHash != parsedJoinRequest.hash {
		return nil, nil, "", fmt.Errorf("join request hash mismatch")
	}
	if !ed25519.Verify(parsedJoinRequest.authPublicKey, parsedJoinRequest.payload, parsedJoinRequest.signature) {
		return nil, nil, "", fmt.Errorf("invalid join request signature")
	}
	inviteSecret, err := protocol.DecodeBase64URLExact("inviteSecret", invite.InviteSecret, protocol.InviteSecretLength)
	if err != nil {
		return nil, nil, "", err
	}
	if err := protocol.VerifyInviteProof(inviteSecret, parsedJoinRequest.payload, parsedJoinRequest.inviteProof); err != nil {
		return nil, nil, "", err
	}
	inviteServerSecret, err := protocol.DeriveInviteServerSecret(inviteSecret)
	if err != nil {
		return nil, nil, "", err
	}
	return parsedJoinRequest.wrapPublicKey, inviteServerSecret, parsedJoinRequest.hash, nil
}
