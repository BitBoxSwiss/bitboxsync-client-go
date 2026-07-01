// SPDX-License-Identifier: Apache-2.0

package protocol

import "time"

// HealthResponse reports basic process health.
type HealthResponse struct {
	// Status is the process health string. The server returns "ok" when ready.
	Status string `json:"status"`
}

// VersionResponse reports build metadata for deployment verification.
type VersionResponse struct {
	// GitCommit is the git commit hash the server binary was built from.
	GitCommit string `json:"gitCommit"`
}

// SpamControl describes the anti-abuse proof the client must provide.
type SpamControl struct {
	// Kind names the anti-abuse mode, such as "none" or "attestation".
	Kind string `json:"kind"`
}

// ChallengeRequest asks the server to mint a challenge for one auth purpose.
type ChallengeRequest struct {
	// Purpose selects the auth flow the challenge is for, such as login or
	// refresh.
	Purpose string `json:"purpose"`
	// Kind identifies the auth-key kind requesting the challenge.
	Kind string `json:"kind"`
	// Action optionally binds a sensitive-action challenge to one action name.
	Action string `json:"action,omitempty"`
	// ActionFieldsHash is the optional lowercase-hex SHA-256 hash of the
	// canonical sensitive-action fields.
	ActionFieldsHash string `json:"actionFieldsHash,omitempty"`
}

// ChallengeResponse returns a fresh challenge and its spam-control policy.
type ChallengeResponse struct {
	// Challenge is the base64-encoded random challenge payload to sign.
	Challenge string `json:"challenge"`
	// ExpiresAt is when the challenge becomes invalid server-side.
	ExpiresAt time.Time `json:"expiresAt"`
	// SpamControl tells the client what additional proof to attach.
	SpamControl SpamControl `json:"spamControl"`
}

// LoginRequest carries the signed login payload for a device identity.
type LoginRequest struct {
	// Kind identifies the auth-key kind being used to log in.
	Kind string `json:"kind"`
	// KeyID is the hex-encoded key identifier derived from AuthPublicKey.
	KeyID string `json:"keyId"`
	// AuthPublicKey is the hex-encoded Ed25519 public key for auth intents.
	AuthPublicKey string `json:"authPublicKey"`
	// WrapPublicKey is the hex-encoded X25519 public key for namespace DEK
	// wrapping.
	WrapPublicKey string `json:"wrapPublicKey"`
	// Challenge is the base64-encoded challenge received from Challenge.
	Challenge string `json:"challenge"`
	// IntentSignature is the hex-encoded signature over the canonical login
	// intent.
	IntentSignature string `json:"intentSignature"`
	// Attestation is an optional base64-encoded anti-abuse proof required when
	// spam control is set to attestation.
	Attestation string `json:"attestation,omitempty"`
}

// LoginResponse returns the bearer token and default-namespace hint after
// successful login.
type LoginResponse struct {
	// Kind echoes the authenticated auth-key kind.
	Kind string `json:"kind"`
	// AccessToken is the opaque bearer token to use for authenticated API calls.
	AccessToken string `json:"accessToken"`
	// ExpiresAt is when AccessToken expires server-side.
	ExpiresAt time.Time `json:"expiresAt"`
	// DefaultNamespaceID, when non-nil, names the caller's default namespace.
	DefaultNamespaceID *string `json:"defaultNamespaceId"`
}

// RefreshRequest carries the signed refresh payload for a device identity.
type RefreshRequest struct {
	// Kind identifies the auth-key kind being refreshed.
	Kind string `json:"kind"`
	// KeyID is the hex-encoded key identifier derived from the auth public key.
	KeyID string `json:"keyId"`
	// Challenge is the base64-encoded challenge received from Challenge.
	Challenge string `json:"challenge"`
	// IntentSignature is the hex-encoded signature over the canonical refresh
	// intent.
	IntentSignature string `json:"intentSignature"`
	// Attestation is an optional base64-encoded anti-abuse proof required when
	// spam control is set to attestation.
	Attestation string `json:"attestation,omitempty"`
}

// RefreshResponse returns a replacement bearer token after refresh.
type RefreshResponse struct {
	// Kind echoes the authenticated auth-key kind.
	Kind string `json:"kind"`
	// AccessToken is the new opaque bearer token.
	AccessToken string `json:"accessToken"`
	// ExpiresAt is when AccessToken expires server-side.
	ExpiresAt time.Time `json:"expiresAt"`
}

// RevokeAllTokensRequest carries the signed sensitive-action payload required
// to revoke every bearer token for the current identity.
type RevokeAllTokensRequest struct {
	// Kind identifies the auth-key kind authorizing token revocation.
	Kind string `json:"kind"`
	// KeyID is the hex-encoded key identifier of the authenticated identity.
	KeyID string `json:"keyId"`
	// Challenge is the base64-encoded sensitive-action challenge.
	Challenge string `json:"challenge"`
	// IntentSignature is the hex-encoded signature over the canonical sensitive
	// action intent for revoke-all-tokens.
	IntentSignature string `json:"intentSignature"`
}

// DefaultNamespaceResponse returns the authenticated identity's default
// namespace metadata.
type DefaultNamespaceResponse struct {
	// NamespaceID is the hex-encoded identifier of the default namespace.
	NamespaceID string `json:"namespaceId"`
	// Kind is the namespace kind and is expected to be "default".
	Kind string `json:"kind"`
}

// EnsureDefaultNamespaceRequest proposes and wraps a default namespace for the
// authenticated identity.
type EnsureDefaultNamespaceRequest struct {
	// ProposedNamespaceID is the caller-chosen namespace ID to create if the
	// default namespace does not already exist.
	ProposedNamespaceID string `json:"proposedNamespaceId"`
	// WrappedDEK is the base64-encoded namespace DEK wrapped for the caller.
	WrappedDEK string `json:"wrappedDek"`
}

// EnsureDefaultNamespaceResponse returns the final default namespace assignment.
type EnsureDefaultNamespaceResponse struct {
	// NamespaceID is the hex-encoded identifier of the default namespace.
	NamespaceID string `json:"namespaceId"`
	// Kind is the namespace kind and is expected to be "default".
	Kind string `json:"kind"`
	// WrappedDEK is the base64-encoded namespace DEK wrapped for the caller.
	WrappedDEK string `json:"wrappedDek"`
	// Created reports whether the namespace was created by this call.
	Created bool `json:"created"`
}

// NamespaceSummary describes one namespace visible to an identity.
type NamespaceSummary struct {
	// NamespaceID is the hex-encoded namespace identifier.
	NamespaceID string `json:"namespaceId"`
	// Kind is the namespace kind, such as "default" or "shared".
	Kind string `json:"kind"`
	// NamespaceHead is the current namespace change counter.
	NamespaceHead uint64 `json:"namespaceHead"`
}

// ListNamespacesResponse returns all namespaces visible to an identity.
type ListNamespacesResponse struct {
	// Namespaces contains one summary per namespace visible to the caller.
	Namespaces []NamespaceSummary `json:"namespaces"`
}

// WatchNamespacesRequest asks the server to wait until one of the caller's
// visible namespaces differs from the supplied namespace-head checkpoint.
type WatchNamespacesRequest struct {
	// KnownHeads maps namespace IDs to the latest namespaceHead value the
	// client has already reconciled. Visible namespaces missing from this map are
	// treated as changed and are returned immediately.
	KnownHeads map[string]uint64 `json:"knownHeads"`
}

// WatchNamespacesResponse returns namespaces whose current head differs from
// the request checkpoint, or an empty list when the server-side wait timed out.
type WatchNamespacesResponse struct {
	// Namespaces contains visible namespaces whose namespaceHead differs from
	// the request's knownHeads map, including newly visible namespaces.
	Namespaces []NamespaceSummary `json:"namespaces"`
	// TimedOut reports that the long poll reached the server-side timeout
	// without observing a relevant change.
	TimedOut bool `json:"timedOut"`
}

// CreateSharedNamespaceRequest creates a new shared namespace with the caller's
// wrapped DEK.
type CreateSharedNamespaceRequest struct {
	// NamespaceID is the caller-chosen hex-encoded namespace identifier.
	NamespaceID string `json:"namespaceId"`
	// WrappedDEK is the base64-encoded namespace DEK wrapped for the caller.
	WrappedDEK string `json:"wrappedDek"`
}

// CreateSharedNamespaceResponse returns metadata for a newly created shared
// namespace.
type CreateSharedNamespaceResponse struct {
	// NamespaceID is the hex-encoded identifier of the created namespace.
	NamespaceID string `json:"namespaceId"`
	// Kind is the namespace kind and is expected to be "shared".
	Kind string `json:"kind"`
	// Created reports whether the namespace was created by this call.
	Created bool `json:"created"`
}

// NamespaceMember identifies one namespace member.
type NamespaceMember struct {
	// Kind is the member's auth-key kind.
	Kind string `json:"kind"`
	// KeyID is the member's hex-encoded key identifier.
	KeyID string `json:"keyId"`
}

// GetNamespaceMembersResponse returns the membership list for a namespace.
type GetNamespaceMembersResponse struct {
	// NamespaceID is the hex-encoded namespace identifier.
	NamespaceID string `json:"namespaceId"`
	// Members lists all current namespace members.
	Members []NamespaceMember `json:"members"`
}

// NamespaceInviteToken is the app-visible invite material encoded into a QR
// code or copyable URI. InviteSecret must never be sent to the server directly.
type NamespaceInviteToken struct {
	Version      int
	ServerOrigin string
	NamespaceID  string
	InviteID     string
	ExpiresAt    int64
	InviteSecret string
}

// CreateNamespaceInviteRequest creates a short-lived invite for one shared
// namespace.
type CreateNamespaceInviteRequest struct {
	Kind                   string `json:"kind"`
	KeyID                  string `json:"keyId"`
	InviteID               string `json:"inviteId"`
	InviteServerSecretHash string `json:"inviteServerSecretHash"`
	Challenge              string `json:"challenge"`
	IntentSignature        string `json:"intentSignature"`
	ExpiresAt              int64  `json:"expiresAt"`
	MaxAccepted            int    `json:"maxAccepted"`
}

// CreateNamespaceInviteResponse reports the stored invite metadata.
type CreateNamespaceInviteResponse struct {
	NamespaceID string `json:"namespaceId"`
	InviteID    string `json:"inviteId"`
	ExpiresAt   int64  `json:"expiresAt"`
	MaxAccepted int    `json:"maxAccepted"`
}

// NamespaceInviteSummary describes one namespace invite visible to members.
type NamespaceInviteSummary struct {
	InviteID           string     `json:"inviteId"`
	CreatedByKeyID     string     `json:"createdByKeyId"`
	CreatedAt          time.Time  `json:"createdAt"`
	ExpiresAt          int64      `json:"expiresAt"`
	MaxAccepted        int        `json:"maxAccepted"`
	ActiveRequestCount int        `json:"activeRequestCount"`
	AcceptedCount      int        `json:"acceptedCount"`
	RevokedAt          *time.Time `json:"revokedAt"`
}

// ListNamespaceInvitesResponse returns invite-management rows for a namespace.
type ListNamespaceInvitesResponse struct {
	NamespaceID string                   `json:"namespaceId"`
	Invites     []NamespaceInviteSummary `json:"invites"`
}

// NamespaceJoinRequest is the signed request material submitted by a
// prospective member and later verified by an approver.
type NamespaceJoinRequest struct {
	Version       int    `json:"version"`
	NamespaceID   string `json:"namespaceId"`
	InviteID      string `json:"inviteId"`
	ServerOrigin  string `json:"serverOrigin"`
	Kind          string `json:"kind"`
	KeyID         string `json:"keyId"`
	AuthPublicKey string `json:"authPublicKey"`
	WrapPublicKey string `json:"wrapPublicKey"`
	ExpiresAt     int64  `json:"expiresAt"`
	Signature     string `json:"signature"`
	InviteProof   string `json:"inviteProof"`
}

// SubmitNamespaceJoinRequestRequest submits one signed join request through an
// invite.
type SubmitNamespaceJoinRequestRequest struct {
	InviteServerSecret string               `json:"inviteServerSecret"`
	JoinRequest        NamespaceJoinRequest `json:"joinRequest"`
}

// SubmitNamespaceJoinRequestResponse reports the stored pending join request.
type SubmitNamespaceJoinRequestResponse struct {
	NamespaceID     string `json:"namespaceId"`
	InviteID        string `json:"inviteId"`
	RequesterKind   string `json:"requesterKind"`
	RequesterKeyID  string `json:"requesterKeyId"`
	JoinRequestHash string `json:"joinRequestHash"`
	Status          string `json:"status"`
}

// NamespaceJoinRequestEntry is one pending request visible to namespace members.
type NamespaceJoinRequestEntry struct {
	InviteID        string               `json:"inviteId"`
	JoinRequestHash string               `json:"joinRequestHash"`
	CreatedAt       time.Time            `json:"createdAt"`
	Status          string               `json:"status"`
	JoinRequest     NamespaceJoinRequest `json:"joinRequest"`
}

// ListNamespaceJoinRequestsResponse lists pending namespace join requests.
type ListNamespaceJoinRequestsResponse struct {
	NamespaceID string                      `json:"namespaceId"`
	Requests    []NamespaceJoinRequestEntry `json:"requests"`
}

// ApproveNamespaceJoinRequestRequest approves a pending join request.
type ApproveNamespaceJoinRequestRequest struct {
	InviteServerSecret string `json:"inviteServerSecret"`
	WrappedDEK         string `json:"wrappedDek"`
}

// ApproveNamespaceJoinRequestResponse reports the membership created by
// approval.
type ApproveNamespaceJoinRequestResponse struct {
	NamespaceID     string `json:"namespaceId"`
	MemberKind      string `json:"memberKind"`
	MemberKeyID     string `json:"memberKeyId"`
	JoinRequestHash string `json:"joinRequestHash"`
}

// RejectNamespaceJoinRequestResponse reports request rejection.
type RejectNamespaceJoinRequestResponse struct {
	NamespaceID     string `json:"namespaceId"`
	RequesterKeyID  string `json:"requesterKeyId"`
	JoinRequestHash string `json:"joinRequestHash"`
	Rejected        bool   `json:"rejected"`
}

// RevokeNamespaceInviteResponse reports invite revocation.
type RevokeNamespaceInviteResponse struct {
	NamespaceID string `json:"namespaceId"`
	InviteID    string `json:"inviteId"`
	Revoked     bool   `json:"revoked"`
}

// GetWrappedDEKResponse returns the wrapped namespace DEK for one member.
type GetWrappedDEKResponse struct {
	// NamespaceID is the hex-encoded namespace identifier.
	NamespaceID string `json:"namespaceId"`
	// KeyID is the hex-encoded member key identifier.
	KeyID string `json:"keyId"`
	// WrappedDEK is the base64-encoded namespace DEK wrapped for KeyID.
	WrappedDEK string `json:"wrappedDek"`
}

// NamespaceItemVersion describes the current version metadata for one item in a
// namespace snapshot.
type NamespaceItemVersion struct {
	// Version is the current monotonically increasing version of the item.
	Version uint64 `json:"version"`
}

// GetNamespaceItemsResponse returns the authoritative item/version snapshot for
// a namespace.
type GetNamespaceItemsResponse struct {
	// NamespaceID is the hex-encoded namespace identifier.
	NamespaceID string `json:"namespaceId"`
	// NamespaceHead is the current namespace change counter.
	NamespaceHead uint64 `json:"namespaceHead"`
	// Items maps each hex-encoded item ID to its current version metadata.
	Items map[string]NamespaceItemVersion `json:"items"`
}

// GetItemResponse returns one encrypted item and its current version.
type GetItemResponse struct {
	// NamespaceID is the hex-encoded namespace identifier.
	NamespaceID string `json:"namespaceId"`
	// ItemID is the hex-encoded item identifier.
	ItemID string `json:"itemId"`
	// Version is the current stored version of the item.
	Version uint64 `json:"version"`
	// Nonce is the base64-encoded AEAD nonce used for Ciphertext.
	Nonce string `json:"nonce"`
	// AAD is the base64-encoded associated data bound to NamespaceID, ItemID, and
	// Version.
	AAD string `json:"aad"`
	// Ciphertext is the base64-encoded encrypted item payload.
	Ciphertext string `json:"ciphertext"`
}

// PutItemRequest carries one encrypted item write.
type PutItemRequest struct {
	// Nonce is the base64-encoded AEAD nonce used for Ciphertext.
	Nonce string `json:"nonce"`
	// AAD is the base64-encoded associated data bound to the target version.
	AAD string `json:"aad"`
	// Ciphertext is the base64-encoded encrypted item payload.
	Ciphertext string `json:"ciphertext"`
}

// PutItemResponse reports the stored version of one encrypted item write.
type PutItemResponse struct {
	// NamespaceID is the hex-encoded namespace identifier.
	NamespaceID string `json:"namespaceId"`
	// ItemID is the hex-encoded item identifier.
	ItemID string `json:"itemId"`
	// Version is the version stored by the server after the write.
	Version uint64 `json:"version"`
}
