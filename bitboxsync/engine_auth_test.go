// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/stretchr/testify/require"
)

func TestSyncNowRelogsInAndRetriesAfterUnauthorizedToken(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	// Regression test for locally valid but server-rejected bearer tokens. This
	// can happen when a token is revoked, expired server-side, or lost during a
	// server restore while the client still has a future TokenExpiry. SyncNow
	// must not keep polling forever with the stale token; it should perform one
	// fresh login and retry the reconciliation pass with the replacement token.
	state := engine.identityStateSnapshot()
	state.AccessToken = "revoked-token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	state.UpdatedAt = time.Now().UTC()
	require.NoError(t, engine.saveIdentityState(ctx, state))

	challenge := make([]byte, 32)
	challenge[0] = 42
	var namespaceListCalls int
	var loginCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/mine":
			namespaceListCalls++
			switch r.Header.Get("Authorization") {
			case "Bearer revoked-token":
				writeUnauthorized(t, w)
			case "Bearer fresh-token":
				writeTestJSON(t, w, protocol.ListNamespacesResponse{
					Namespaces: []protocol.NamespaceSummary{{
						NamespaceID:   namespace.ID(),
						Kind:          protocol.NamespaceKindDefault,
						NamespaceHead: 0,
					}},
				})
			default:
				require.Failf(t, "unexpected Authorization header", "%q", r.Header.Get("Authorization"))
			}
		case "/v1/auth/challenge":
			writeTestJSON(t, w, protocol.ChallengeResponse{
				Challenge: protocol.EncodeBase64(challenge),
				ExpiresAt: time.Now().UTC().Add(time.Minute),
				SpamControl: protocol.SpamControl{
					Kind: protocol.SpamControlKindNone,
				},
			})
		case "/v1/auth/login":
			loginCalls++
			writeTestJSON(t, w, protocol.LoginResponse{
				Kind:        protocol.IdentityKindKeystore,
				AccessToken: "fresh-token",
				ExpiresAt:   time.Now().UTC().Add(time.Hour),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.SyncNow(ctx))
	require.Equal(t, 2, namespaceListCalls)
	require.Equal(t, 1, loginCalls)
	state = engine.identityStateSnapshot()
	require.Equal(t, "fresh-token", state.AccessToken)

	events := drainEvents(engine)
	require.False(t, hasEventType(events, EventAuthLoginRequired))
	require.True(t, hasEventType(events, EventAuthSessionReady))
}

func TestSyncNowUsesUnexpiredTokenWhenProactiveRefreshFails(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	engine.cfg.RefreshSkew = 24 * time.Hour

	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	state := engine.identityStateSnapshot()
	state.AccessToken = "still-valid-token"
	state.TokenExpiry = expiresAt
	state.UpdatedAt = time.Now().UTC()
	require.NoError(t, engine.saveIdentityState(ctx, state))

	var challengeCalls int
	var loginCalls int
	var namespaceListCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/challenge":
			challengeCalls++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(`{"error":"refresh temporarily unavailable"}`))
			require.NoError(t, err)
		case "/v1/auth/login":
			loginCalls++
			http.NotFound(w, r)
		case "/v1/namespaces/mine":
			namespaceListCalls++
			require.Equal(t, "Bearer still-valid-token", r.Header.Get("Authorization"))
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 0,
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.SyncNow(ctx))
	require.Equal(t, 1, challengeCalls)
	require.Equal(t, 0, loginCalls)
	require.Equal(t, 1, namespaceListCalls)
	require.Equal(t, "still-valid-token", engine.identityStateSnapshot().AccessToken)

	events := drainEvents(engine)
	refreshEvent := requireEventType(t, events, EventAuthRefreshRecommended)
	require.True(t, refreshEvent.TokenExpiresAt.Equal(expiresAt))
	require.False(t, hasEventType(events, EventAuthSessionReady))
}

func TestSyncNowEmitsSessionReadyAfterSuccessfulLogin(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	challenge := make([]byte, 32)
	challenge[0] = 5
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/challenge":
			writeTestJSON(t, w, protocol.ChallengeResponse{
				Challenge: protocol.EncodeBase64(challenge),
				ExpiresAt: time.Now().UTC().Add(time.Minute),
				SpamControl: protocol.SpamControl{
					Kind: protocol.SpamControlKindNone,
				},
			})
		case "/v1/auth/login":
			writeTestJSON(t, w, protocol.LoginResponse{
				Kind:        protocol.IdentityKindKeystore,
				AccessToken: "fresh-token",
				ExpiresAt:   expiresAt,
			})
		case "/v1/namespaces/mine":
			require.Equal(t, "Bearer fresh-token", r.Header.Get("Authorization"))
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 0,
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.SyncNow(ctx))
	events := drainEvents(engine)
	require.False(t, hasEventType(events, EventAuthLoginRequired))
	sessionReadyEvent := requireEventType(t, events, EventAuthSessionReady)
	require.True(t, sessionReadyEvent.TokenExpiresAt.Equal(expiresAt))
}

func TestSyncNowEmitsLoginRequiredAfterLoginFailure(t *testing.T) {
	ctx := context.Background()
	engine, _, _ := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/challenge" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(`{"error":"login unavailable"}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.Error(t, engine.SyncNow(ctx))
	events := drainEvents(engine)
	loginRequiredEvent := requireEventType(t, events, EventAuthLoginRequired)
	require.True(t, loginRequiredEvent.TokenExpiresAt.IsZero())
	syncFailedEvent := requireEventType(t, events, EventSyncFailed)
	require.Error(t, syncFailedEvent.Err)
}

func TestSyncNowEmitsAuthEventsForSuccessfulRefresh(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)
	engine.cfg.RefreshSkew = 24 * time.Hour

	oldExpiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	newExpiresAt := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	state := engine.identityStateSnapshot()
	state.AccessToken = "expiring-token"
	state.TokenExpiry = oldExpiresAt
	state.UpdatedAt = time.Now().UTC()
	require.NoError(t, engine.saveIdentityState(ctx, state))

	challenge := make([]byte, 32)
	challenge[0] = 6
	var refreshCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/challenge":
			writeTestJSON(t, w, protocol.ChallengeResponse{
				Challenge: protocol.EncodeBase64(challenge),
				ExpiresAt: time.Now().UTC().Add(time.Minute),
				SpamControl: protocol.SpamControl{
					Kind: protocol.SpamControlKindNone,
				},
			})
		case "/v1/auth/refresh":
			refreshCalls++
			require.Equal(t, "Bearer expiring-token", r.Header.Get("Authorization"))
			writeTestJSON(t, w, protocol.RefreshResponse{
				Kind:        protocol.IdentityKindKeystore,
				AccessToken: "refreshed-token",
				ExpiresAt:   newExpiresAt,
			})
		case "/v1/namespaces/mine":
			require.Equal(t, "Bearer refreshed-token", r.Header.Get("Authorization"))
			writeTestJSON(t, w, protocol.ListNamespacesResponse{
				Namespaces: []protocol.NamespaceSummary{{
					NamespaceID:   namespace.ID(),
					Kind:          protocol.NamespaceKindDefault,
					NamespaceHead: 0,
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	require.NoError(t, engine.SyncNow(ctx))
	require.Equal(t, 1, refreshCalls)
	state = engine.identityStateSnapshot()
	require.Equal(t, "refreshed-token", state.AccessToken)
	require.True(t, state.TokenExpiry.Equal(newExpiresAt))

	events := drainEvents(engine)
	refreshEvent := requireEventType(t, events, EventAuthRefreshRecommended)
	require.True(t, refreshEvent.TokenExpiresAt.Equal(oldExpiresAt))
	sessionReadyEvent := requireEventType(t, events, EventAuthSessionReady)
	require.True(t, sessionReadyEvent.TokenExpiresAt.Equal(newExpiresAt))
}

func TestListNamespacesRelogsInAfterUnauthorizedToken(t *testing.T) {
	ctx := context.Background()
	engine, _, namespace := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	state := engine.identityStateSnapshot()
	state.AccessToken = "revoked-token"
	state.TokenExpiry = time.Now().UTC().Add(48 * time.Hour)
	state.UpdatedAt = time.Now().UTC()
	require.NoError(t, engine.saveIdentityState(ctx, state))

	challenge := make([]byte, 32)
	challenge[0] = 7
	var namespaceListCalls int
	var loginCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/mine":
			namespaceListCalls++
			switch r.Header.Get("Authorization") {
			case "Bearer revoked-token":
				writeUnauthorized(t, w)
			case "Bearer fresh-token":
				writeTestJSON(t, w, protocol.ListNamespacesResponse{
					Namespaces: []protocol.NamespaceSummary{{
						NamespaceID:   namespace.ID(),
						Kind:          protocol.NamespaceKindDefault,
						NamespaceHead: 0,
					}},
				})
			default:
				require.Failf(t, "unexpected Authorization header", "%q", r.Header.Get("Authorization"))
			}
		case "/v1/auth/challenge":
			writeTestJSON(t, w, protocol.ChallengeResponse{
				Challenge: protocol.EncodeBase64(challenge),
				ExpiresAt: time.Now().UTC().Add(time.Minute),
				SpamControl: protocol.SpamControl{
					Kind: protocol.SpamControlKindNone,
				},
			})
		case "/v1/auth/login":
			loginCalls++
			writeTestJSON(t, w, protocol.LoginResponse{
				Kind:        protocol.IdentityKindKeystore,
				AccessToken: "fresh-token",
				ExpiresAt:   time.Now().UTC().Add(time.Hour),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	namespaces, err := engine.ListNamespaces(ctx)
	require.NoError(t, err)
	require.Len(t, namespaces, 1)
	require.Equal(t, 2, namespaceListCalls)
	require.Equal(t, 1, loginCalls)
	require.Equal(t, "fresh-token", engine.identityStateSnapshot().AccessToken)
}

func TestJoinNamespaceAuthenticatesBeforeFetchingWrappedDEK(t *testing.T) {
	ctx := context.Background()
	engine, _, _ := newTestEngine(t, ctx)
	defer closeTestEngine(t, engine)

	namespaceIDRaw, err := protocol.RandomNamespaceID()
	require.NoError(t, err)
	namespaceID := hex.EncodeToString(namespaceIDRaw)
	namespaceDEK, err := protocol.RandomNamespaceDEK()
	require.NoError(t, err)
	wrappedDEK, err := wrapNamespaceDEKFor(namespaceID, namespaceDEK, engine.identity.WrapPublicKey())
	require.NoError(t, err)

	challenge := make([]byte, 32)
	challenge[0] = 9
	var loginCalls int
	var wrappedDEKCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/challenge":
			writeTestJSON(t, w, protocol.ChallengeResponse{
				Challenge: protocol.EncodeBase64(challenge),
				ExpiresAt: time.Now().UTC().Add(time.Minute),
				SpamControl: protocol.SpamControl{
					Kind: protocol.SpamControlKindNone,
				},
			})
		case "/v1/auth/login":
			loginCalls++
			writeTestJSON(t, w, protocol.LoginResponse{
				Kind:        protocol.IdentityKindKeystore,
				AccessToken: "fresh-token",
				ExpiresAt:   time.Now().UTC().Add(time.Hour),
			})
		case "/v1/namespaces/" + namespaceID + "/wrapped-deks/" + engine.keyID:
			wrappedDEKCalls++
			require.Equal(t, "Bearer fresh-token", r.Header.Get("Authorization"))
			writeTestJSON(t, w, protocol.GetWrappedDEKResponse{
				NamespaceID: namespaceID,
				KeyID:       engine.keyID,
				WrappedDEK:  protocol.EncodeBase64(wrappedDEK),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	engine.client = newTestRawClient(t, server)

	joined, err := engine.JoinNamespace(ctx, namespaceID)
	require.NoError(t, err)
	require.Equal(t, namespaceID, joined.ID())
	require.Equal(t, 1, loginCalls)
	require.Equal(t, 1, wrappedDEKCalls)
}

func writeUnauthorized(t *testing.T, w http.ResponseWriter) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "invalid bearer token"}))
}

func requireEventType(t *testing.T, events []Event, eventType EventType) Event {
	t.Helper()

	for _, event := range events {
		if event.Type == eventType {
			return event
		}
	}
	require.Failf(t, "missing event", "event type %q not found in %#v", eventType, events)
	return Event{}
}
