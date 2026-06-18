// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/stretchr/testify/require"
)

func TestCreateInviteReturnsTokenAndSubmitsAction(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestNamespaceKind(t, ctx, store, engine, namespace, protocol.NamespaceKindShared)
	setTestAccessToken(t, ctx, engine)

	inviteID := strings.Repeat("22", protocol.InviteIDLength)
	inviteSecret := protocol.EncodeBase64URL(bytes.Repeat([]byte{0x33}, protocol.InviteSecretLength))
	opts := NamespaceInviteOptions{
		ServerOrigin: "https://sync.example",
		InviteID:     inviteID,
		InviteSecret: inviteSecret,
	}

	var challengeCalls int
	var requests []protocol.CreateNamespaceInviteRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/challenge":
			challengeCalls++
			var req protocol.ChallengeRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			require.Equal(t, protocol.ChallengePurposeSensitiveAction, req.Purpose)
			require.Equal(t, protocol.SensitiveActionCreateNamespaceInvite, req.Action)
			challenge := bytes.Repeat([]byte{byte(0x30 + challengeCalls)}, 32)
			writeTestJSON(t, w, protocol.ChallengeResponse{
				Challenge: protocol.EncodeBase64(challenge),
				ExpiresAt: time.Now().UTC().Add(time.Minute),
				SpamControl: protocol.SpamControl{
					Kind: protocol.SpamControlKindNone,
				},
			})
		case "/v1/namespaces/" + namespace.ID() + "/invites":
			require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			var req protocol.CreateNamespaceInviteRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			requests = append(requests, req)
			writeTestJSON(t, w, protocol.CreateNamespaceInviteResponse{
				NamespaceID: namespace.ID(),
				InviteID:    inviteID,
				ExpiresAt:   req.ExpiresAt,
				MaxPending:  req.MaxPending,
				MaxAccepted: req.MaxAccepted,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	token, err := namespace.CreateInvite(ctx, opts)
	require.NoError(t, err)
	require.Equal(t, 1, challengeCalls)
	require.Len(t, requests, 1)
	require.Equal(t, protocol.NamespaceInviteToken{
		Version:      protocol.NamespaceJoinRequestVersion,
		ServerOrigin: "https://sync.example",
		NamespaceID:  namespace.ID(),
		InviteID:     inviteID,
		ExpiresAt:    requests[0].ExpiresAt,
		InviteSecret: inviteSecret,
	}, token)
	require.NotEmpty(t, requests[0].Challenge)
	require.NotEmpty(t, requests[0].IntentSignature)
}

func TestCreateInviteRejectsDefaultNamespaceBeforeChallenge(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestAccessToken(t, ctx, engine)

	var challengeCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/challenge" {
			challengeCalls++
		}
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	_, err := namespace.CreateInvite(ctx, NamespaceInviteOptions{
		ServerOrigin: "https://sync.example",
	})
	require.ErrorContains(t, err, "expected shared")
	require.Equal(t, 0, challengeCalls)
}

func TestCreateInviteRejectsUnknownNamespaceKindBeforeChallenge(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestNamespaceKind(t, ctx, store, engine, namespace, "")
	setTestAccessToken(t, ctx, engine)

	var challengeCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/challenge" {
			challengeCalls++
		}
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	_, err := namespace.CreateInvite(ctx, NamespaceInviteOptions{
		ServerOrigin: "https://sync.example",
	})
	require.ErrorContains(t, err, "expected shared")
	require.Equal(t, 0, challengeCalls)
}

func TestCreateInviteRejectsValuesOutsideProtocolPolicy(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	_, err := namespace.CreateInvite(ctx, NamespaceInviteOptions{
		ServerOrigin: "https://sync.example",
		TTL:          protocol.MaxInviteTTL + time.Second,
	})
	require.ErrorContains(t, err, "invite ttl exceeds maximum")

	_, err = namespace.CreateInvite(ctx, NamespaceInviteOptions{
		ServerOrigin: "https://sync.example",
		MaxPending:   protocol.MaxPendingJoinRequestsPerInvite + 1,
	})
	require.ErrorContains(t, err, "maxPending exceeds maximum")

	_, err = namespace.CreateInvite(ctx, NamespaceInviteOptions{
		ServerOrigin: "https://sync.example",
		MaxAccepted:  protocol.MaxAcceptedJoinRequestsPerInvite + 1,
	})
	require.ErrorContains(t, err, "maxAccepted exceeds maximum")
}

func TestCreateInviteRejectsResponseParameterMismatch(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*protocol.CreateNamespaceInviteResponse)
		wantErr string
	}{
		{
			name: "expires at",
			mutate: func(resp *protocol.CreateNamespaceInviteResponse) {
				resp.ExpiresAt++
			},
			wantErr: "expiry mismatch",
		},
		{
			name: "max pending",
			mutate: func(resp *protocol.CreateNamespaceInviteResponse) {
				resp.MaxPending++
			},
			wantErr: "maxPending mismatch",
		},
		{
			name: "max accepted",
			mutate: func(resp *protocol.CreateNamespaceInviteResponse) {
				resp.MaxAccepted++
			},
			wantErr: "maxAccepted mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			engine, store, namespace := newTestEngine(t, ctx)
			defer closeTestEngine(t, engine)
			setTestNamespaceKind(t, ctx, store, engine, namespace, protocol.NamespaceKindShared)
			setTestAccessToken(t, ctx, engine)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/challenge":
					writeTestJSON(t, w, protocol.ChallengeResponse{
						Challenge: protocol.EncodeBase64(bytes.Repeat([]byte{0x31}, 32)),
						ExpiresAt: time.Now().UTC().Add(time.Minute),
						SpamControl: protocol.SpamControl{
							Kind: protocol.SpamControlKindNone,
						},
					})
				case "/v1/namespaces/" + namespace.ID() + "/invites":
					var req protocol.CreateNamespaceInviteRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
					resp := protocol.CreateNamespaceInviteResponse{
						NamespaceID: namespace.ID(),
						InviteID:    req.InviteID,
						ExpiresAt:   req.ExpiresAt,
						MaxPending:  req.MaxPending,
						MaxAccepted: req.MaxAccepted,
					}
					tt.mutate(&resp)
					writeTestJSON(t, w, resp)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			engine.client = newTestRawClient(t, server)

			_, err := namespace.CreateInvite(ctx, NamespaceInviteOptions{
				ServerOrigin: "https://sync.example",
			})
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSubmitJoinRequestRejectsUnsupportedInviteVersion(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	invite := testInvite(namespace.ID())
	invite.Version = protocol.NamespaceJoinRequestVersion + 1

	_, err := engine.SubmitJoinRequest(ctx, invite, NamespaceJoinRequestOptions{})
	require.ErrorIs(t, err, protocol.ErrUnsupportedVersion)
}

func TestSubmitJoinRequestRejectsNonCanonicalInviteOrigin(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	invite := testInvite(namespace.ID())
	invite.ServerOrigin = "https://sync.example:443"

	_, err := engine.SubmitJoinRequest(ctx, invite, NamespaceJoinRequestOptions{})
	require.ErrorContains(t, err, "canonical")
}

func TestSubmitJoinRequestCapsDefaultExpiryToInviteExpiry(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestAccessToken(t, ctx, engine)

	invite := testInvite(namespace.ID())
	invite.ExpiresAt = time.Now().UTC().Add(2 * time.Minute).Unix()

	var gotExpiresAt int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespace.ID()+"/invites/"+invite.InviteID+"/join-requests", r.URL.Path)
		var req protocol.SubmitNamespaceJoinRequestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		gotExpiresAt = req.JoinRequest.ExpiresAt
		parsed, err := parseNamespaceJoinRequest(req.JoinRequest)
		require.NoError(t, err)
		writeTestJSON(t, w, protocol.SubmitNamespaceJoinRequestResponse{
			NamespaceID:     namespace.ID(),
			InviteID:        invite.InviteID,
			RequesterKind:   req.JoinRequest.Kind,
			RequesterKeyID:  req.JoinRequest.KeyID,
			JoinRequestHash: parsed.hash,
			Status:          protocol.NamespaceJoinRequestStatusPending,
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	_, err := engine.SubmitJoinRequest(ctx, invite, NamespaceJoinRequestOptions{})
	require.NoError(t, err)
	require.Equal(t, invite.ExpiresAt, gotExpiresAt)
}

func TestSubmitJoinRequestRejectsExplicitExpiryAfterInvite(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	invite := testInvite(namespace.ID())
	invite.ExpiresAt = time.Now().UTC().Add(2 * time.Minute).Unix()

	_, err := engine.SubmitJoinRequest(ctx, invite, NamespaceJoinRequestOptions{
		ExpiresAt: invite.ExpiresAt + 1,
	})
	require.ErrorContains(t, err, "join request expires after invite")
}

func TestSubmitJoinRequestRejectsExplicitExpiryAfterMaxTTL(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	invite := testInvite(namespace.ID())
	invite.ExpiresAt = time.Now().UTC().Add(protocol.MaxInviteTTL).Unix()

	_, err := engine.SubmitJoinRequest(ctx, invite, NamespaceJoinRequestOptions{
		ExpiresAt: time.Now().UTC().Add(protocol.MaxJoinRequestTTL + time.Minute).Unix(),
	})
	require.ErrorContains(t, err, "join request expiry exceeds maximum")
}

func TestSubmitJoinRequestAcceptsExistingPendingResponse(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestAccessToken(t, ctx, engine)

	expiresAt := time.Now().UTC().Add(time.Minute).Unix()
	invite := protocol.NamespaceInviteToken{
		Version:      protocol.NamespaceJoinRequestVersion,
		ServerOrigin: "https://sync.example",
		NamespaceID:  namespace.ID(),
		InviteID:     strings.Repeat("22", protocol.InviteIDLength),
		ExpiresAt:    expiresAt,
		InviteSecret: protocol.EncodeBase64URL(bytes.Repeat([]byte{0x44}, protocol.InviteSecretLength)),
	}
	existingInviteID := strings.Repeat("55", protocol.InviteIDLength)
	existingHash := strings.Repeat("04", protocol.JoinRequestHashLength)
	var submitCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/" + namespace.ID() + "/invites/" + invite.InviteID + "/join-requests":
			submitCalls++
			require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			var req protocol.SubmitNamespaceJoinRequestRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			require.Equal(t, expiresAt, req.JoinRequest.ExpiresAt)
			writeTestJSON(t, w, protocol.SubmitNamespaceJoinRequestResponse{
				NamespaceID:     namespace.ID(),
				InviteID:        existingInviteID,
				RequesterKind:   req.JoinRequest.Kind,
				RequesterKeyID:  req.JoinRequest.KeyID,
				JoinRequestHash: existingHash,
				Status:          protocol.NamespaceJoinRequestStatusPending,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	resp, err := engine.SubmitJoinRequest(ctx, invite, NamespaceJoinRequestOptions{
		ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	require.Equal(t, existingInviteID, resp.InviteID)
	require.Equal(t, existingHash, resp.JoinRequestHash)
	require.Equal(t, 1, submitCalls)
}

func TestApproveJoinRequestSubmitsWrappedDEK(t *testing.T) {
	ctx := context.Background()
	engine, store, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	setTestNamespaceKind(t, ctx, store, engine, namespace, protocol.NamespaceKindShared)
	setTestAccessToken(t, ctx, engine)

	invite := testInvite(namespace.ID())
	entry, _ := testJoinRequestEntry(t, namespace.ID(), invite, time.Now().UTC().Add(time.Hour).Unix())
	wantInviteSecret, err := protocol.DecodeBase64URLExact("inviteSecret", invite.InviteSecret, protocol.InviteSecretLength)
	require.NoError(t, err)
	wantInviteServerSecret, err := protocol.DeriveInviteServerSecret(wantInviteSecret)
	require.NoError(t, err)

	var wrappedDEK string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/v1/namespaces/" + namespace.ID() + "/join-requests/" + entry.JoinRequest.KeyID + "/" + entry.JoinRequestHash + "/approve"
		require.Equal(t, wantPath, r.URL.Path)
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		var req protocol.ApproveNamespaceJoinRequestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, protocol.EncodeBase64URL(wantInviteServerSecret), req.InviteServerSecret)
		wrappedDEK = req.WrappedDEK
		writeTestJSON(t, w, protocol.ApproveNamespaceJoinRequestResponse{
			NamespaceID:     namespace.ID(),
			MemberKind:      protocol.IdentityKindKeystore,
			MemberKeyID:     entry.JoinRequest.KeyID,
			JoinRequestHash: entry.JoinRequestHash,
		})
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, namespace.ApproveJoinRequest(ctx, invite, entry))
	decodedWrappedDEK, err := protocol.DecodeBase64("wrappedDek", wrappedDEK)
	require.NoError(t, err)
	require.NoError(t, protocol.ValidateWrappedDEK(decodedWrappedDEK))
}

func TestApproveJoinRequestRejectsDefaultNamespace(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	invite := testInvite(namespace.ID())
	entry, _ := testJoinRequestEntry(t, namespace.ID(), invite, time.Now().UTC().Add(time.Hour).Unix())

	err := namespace.ApproveJoinRequest(ctx, invite, entry)
	require.ErrorContains(t, err, "expected shared")
}

func TestVerifyJoinRequestForApproval(t *testing.T) {
	namespaceID := strings.Repeat("11", protocol.NamespaceIDLength)
	invite := testInvite(namespaceID)
	entry, recipientWrapPublicKey := testJoinRequestEntry(t, namespaceID, invite, 2000)

	gotWrapPublicKey, gotInviteServerSecret, gotHash, err := verifyJoinRequestForApproval(namespaceID, invite, entry, time.Unix(1000, 0).UTC())
	require.NoError(t, err)
	require.Equal(t, recipientWrapPublicKey.Bytes(), gotWrapPublicKey.Bytes())
	wantInviteSecret, err := protocol.DecodeBase64URLExact("inviteSecret", invite.InviteSecret, protocol.InviteSecretLength)
	require.NoError(t, err)
	wantInviteServerSecret, err := protocol.DeriveInviteServerSecret(wantInviteSecret)
	require.NoError(t, err)
	require.Equal(t, wantInviteServerSecret, gotInviteServerSecret)
	require.Equal(t, entry.JoinRequestHash, gotHash)
}

func TestVerifyJoinRequestForApprovalRejectsTampering(t *testing.T) {
	namespaceID := strings.Repeat("11", protocol.NamespaceIDLength)
	invite := testInvite(namespaceID)
	entry, _ := testJoinRequestEntry(t, namespaceID, invite, 2000)

	tests := []struct {
		name    string
		invite  protocol.NamespaceInviteToken
		entry   protocol.NamespaceJoinRequestEntry
		now     time.Time
		wantErr string
	}{
		{
			name: "invite version",
			invite: func() protocol.NamespaceInviteToken {
				tampered := invite
				tampered.Version = protocol.NamespaceJoinRequestVersion + 1
				return tampered
			}(),
			entry:   entry,
			wantErr: "unsupported version",
		},
		{
			name: "invite expired",
			invite: func() protocol.NamespaceInviteToken {
				tampered := invite
				tampered.ExpiresAt = 999
				return tampered
			}(),
			entry:   entry,
			now:     time.Unix(1000, 0).UTC(),
			wantErr: "invite has expired",
		},
		{
			name: "after invite expiry",
			invite: func() protocol.NamespaceInviteToken {
				tampered := invite
				tampered.ExpiresAt = 1500
				return tampered
			}(),
			entry:   entry,
			wantErr: "join request expires after invite",
		},
		{
			name: "invite proof",
			entry: func() protocol.NamespaceJoinRequestEntry {
				tampered := entry
				tampered.JoinRequest.InviteProof = protocol.EncodeBase64URL(bytes.Repeat([]byte{0x99}, protocol.InviteProofLength))
				return tampered
			}(),
			wantErr: "invalid invite proof",
		},
		{
			name: "signature",
			entry: func() protocol.NamespaceJoinRequestEntry {
				tampered := entry
				signature, err := hex.DecodeString(tampered.JoinRequest.Signature)
				require.NoError(t, err)
				signature[0] ^= 0x01
				tampered.JoinRequest.Signature = hex.EncodeToString(signature)
				return tampered
			}(),
			wantErr: "invalid join request signature",
		},
		{
			name: "hash",
			entry: func() protocol.NamespaceJoinRequestEntry {
				tampered := entry
				tampered.JoinRequestHash = strings.Repeat("aa", protocol.JoinRequestHashLength)
				return tampered
			}(),
			wantErr: "join request hash mismatch",
		},
		{
			name: "server origin",
			entry: func() protocol.NamespaceJoinRequestEntry {
				tampered := entry
				tampered.JoinRequest.ServerOrigin = "https://other.example"
				return tampered
			}(),
			wantErr: "join request server origin mismatch",
		},
		{
			name: "non-canonical invite origin",
			invite: func() protocol.NamespaceInviteToken {
				tampered := invite
				tampered.ServerOrigin = "https://sync.example:443"
				return tampered
			}(),
			entry:   entry,
			wantErr: "canonical",
		},
		{
			name: "key id",
			entry: func() protocol.NamespaceJoinRequestEntry {
				tampered := entry
				tampered.JoinRequest.KeyID = strings.Repeat("aa", protocol.KeyIDLength)
				return tampered
			}(),
			wantErr: "key id does not match auth public key",
		},
		{
			name: "uppercase signature",
			entry: func() protocol.NamespaceJoinRequestEntry {
				tampered := entry
				tampered.JoinRequest.Signature = strings.ToUpper(tampered.JoinRequest.Signature)
				return tampered
			}(),
			wantErr: "lowercase hex",
		},
		{
			name:    "expired",
			entry:   entry,
			now:     time.Unix(2000, 0).UTC(),
			wantErr: "join request has expired",
		},
		{
			name: "wrong invite",
			invite: func() protocol.NamespaceInviteToken {
				tampered := invite
				tampered.InviteID = strings.Repeat("22", protocol.InviteIDLength)
				return tampered
			}(),
			entry:   entry,
			wantErr: "join request invite mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testInvite := tt.invite
			if testInvite.InviteID == "" {
				testInvite = invite
			}
			now := tt.now
			if now.IsZero() {
				now = time.Unix(1000, 0).UTC()
			}
			_, _, _, err := verifyJoinRequestForApproval(namespaceID, testInvite, tt.entry, now)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func testInvite(namespaceID string) protocol.NamespaceInviteToken {
	return protocol.NamespaceInviteToken{
		Version:      protocol.NamespaceJoinRequestVersion,
		ServerOrigin: "https://sync.example",
		NamespaceID:  namespaceID,
		InviteID:     strings.Repeat("21", protocol.InviteIDLength),
		ExpiresAt:    time.Now().UTC().Add(protocol.MaxInviteTTL).Unix(),
		InviteSecret: protocol.EncodeBase64URL(bytes.Repeat([]byte{0x44}, protocol.InviteSecretLength)),
	}
}

func testJoinRequestEntry(t *testing.T, namespaceID string, invite protocol.NamespaceInviteToken, expiresAt int64) (protocol.NamespaceJoinRequestEntry, *ecdh.PublicKey) {
	t.Helper()

	namespaceIDRaw, err := protocol.DecodeLowerHexExact("namespaceId", namespaceID, protocol.NamespaceIDLength)
	require.NoError(t, err)
	inviteIDRaw, err := protocol.DecodeLowerHexExact("inviteId", invite.InviteID, protocol.InviteIDLength)
	require.NoError(t, err)
	inviteSecret, err := protocol.DecodeBase64URLExact("inviteSecret", invite.InviteSecret, protocol.InviteSecretLength)
	require.NoError(t, err)
	serverOriginHash, err := protocol.ServerOriginHash(invite.ServerOrigin)
	require.NoError(t, err)

	authPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, ed25519.SeedSize))
	authPublicKey := authPriv.Public().(ed25519.PublicKey)
	keyIDRaw := protocol.KeyIDFromAuthPublicKey(authPublicKey)
	keyID := hex.EncodeToString(keyIDRaw[:])
	wrapPriv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x66}, 32))
	require.NoError(t, err)
	wrapPublicKey := wrapPriv.PublicKey()
	payload, err := protocol.JoinRequestPayload(
		protocol.IdentityKindKeystore,
		namespaceIDRaw,
		inviteIDRaw,
		serverOriginHash,
		keyIDRaw[:],
		authPublicKey,
		wrapPublicKey,
		uint64(expiresAt),
	)
	require.NoError(t, err)
	signature := ed25519.Sign(authPriv, payload)
	inviteProof, err := protocol.InviteProof(inviteSecret, payload)
	require.NoError(t, err)
	joinRequestHash := hex.EncodeToString(protocol.JoinRequestHash(payload))

	return protocol.NamespaceJoinRequestEntry{
		InviteID:        invite.InviteID,
		JoinRequestHash: joinRequestHash,
		CreatedAt:       time.Unix(900, 0).UTC(),
		Status:          "pending",
		JoinRequest: protocol.NamespaceJoinRequest{
			Version:       protocol.NamespaceJoinRequestVersion,
			NamespaceID:   namespaceID,
			InviteID:      invite.InviteID,
			ServerOrigin:  invite.ServerOrigin,
			Kind:          protocol.IdentityKindKeystore,
			KeyID:         keyID,
			AuthPublicKey: protocol.EncodeEd25519PublicKey(authPublicKey),
			WrapPublicKey: protocol.EncodeX25519PublicKey(wrapPublicKey),
			ExpiresAt:     expiresAt,
			Signature:     hex.EncodeToString(signature),
			InviteProof:   protocol.EncodeBase64URL(inviteProof),
		},
	}, wrapPublicKey
}
