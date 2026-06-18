// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bitboxsync-client-go/protocol"
	"github.com/stretchr/testify/require"
)

func TestGetNamespaceItemsRejectsNamespaceMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	otherNamespaceID := strings.Repeat("02", protocol.NamespaceIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/items", r.URL.Path)
		writeRawTestJSON(t, w, protocol.GetNamespaceItemsResponse{
			NamespaceID:   otherNamespaceID,
			NamespaceHead: 1,
			Items:         map[string]protocol.NamespaceItemVersion{},
		})
	}))

	_, err := client.GetNamespaceItems(ctx, "token", namespaceID)
	require.ErrorContains(t, err, "namespace mismatch")
}

func TestLoginRejectsKindMismatch(t *testing.T) {
	ctx := context.Background()
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/login", r.URL.Path)
		writeRawTestJSON(t, w, protocol.LoginResponse{
			Kind:        "other",
			AccessToken: "token",
		})
	}))

	_, err := client.Login(ctx, protocol.LoginRequest{
		Kind: protocol.IdentityKindKeystore,
	})
	require.ErrorContains(t, err, "kind mismatch")
}

func TestRefreshRejectsKindMismatch(t *testing.T) {
	ctx := context.Background()
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/refresh", r.URL.Path)
		writeRawTestJSON(t, w, protocol.RefreshResponse{
			Kind:        "other",
			AccessToken: "token",
		})
	}))

	_, err := client.Refresh(ctx, "token", protocol.RefreshRequest{
		Kind: protocol.IdentityKindKeystore,
	})
	require.ErrorContains(t, err, "kind mismatch")
}

func TestEnsureDefaultNamespaceRejectsCreatedNamespaceMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	otherNamespaceID := strings.Repeat("02", protocol.NamespaceIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/default", r.URL.Path)
		writeRawTestJSON(t, w, protocol.EnsureDefaultNamespaceResponse{
			NamespaceID: otherNamespaceID,
			Kind:        protocol.NamespaceKindDefault,
			Created:     true,
		})
	}))

	_, err := client.EnsureDefaultNamespace(ctx, "token", protocol.EnsureDefaultNamespaceRequest{
		ProposedNamespaceID: namespaceID,
	})
	require.ErrorContains(t, err, "namespace mismatch")
}

func TestCreateSharedNamespaceRejectsNamespaceMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	otherNamespaceID := strings.Repeat("02", protocol.NamespaceIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces", r.URL.Path)
		writeRawTestJSON(t, w, protocol.CreateSharedNamespaceResponse{
			NamespaceID: otherNamespaceID,
			Kind:        protocol.NamespaceKindShared,
			Created:     true,
		})
	}))

	_, err := client.CreateSharedNamespace(ctx, "token", protocol.CreateSharedNamespaceRequest{
		NamespaceID: namespaceID,
	})
	require.ErrorContains(t, err, "namespace mismatch")
}

func TestGetMembersRejectsNamespaceMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	otherNamespaceID := strings.Repeat("02", protocol.NamespaceIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/members", r.URL.Path)
		writeRawTestJSON(t, w, protocol.GetNamespaceMembersResponse{
			NamespaceID: otherNamespaceID,
		})
	}))

	_, err := client.GetMembers(ctx, "token", namespaceID)
	require.ErrorContains(t, err, "namespace mismatch")
}

func TestCreateNamespaceInviteRejectsInviteMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	inviteID := strings.Repeat("02", protocol.InviteIDLength)
	otherInviteID := strings.Repeat("03", protocol.InviteIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/invites", r.URL.Path)
		writeRawTestJSON(t, w, protocol.CreateNamespaceInviteResponse{
			NamespaceID: namespaceID,
			InviteID:    otherInviteID,
		})
	}))

	_, err := client.CreateNamespaceInvite(ctx, "token", namespaceID, protocol.CreateNamespaceInviteRequest{
		InviteID: inviteID,
	})
	require.ErrorContains(t, err, "invite mismatch")
}

func TestSubmitJoinRequestRejectsInvalidResponseInvite(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	inviteID := strings.Repeat("02", protocol.InviteIDLength)
	joinRequestHash := strings.Repeat("04", protocol.JoinRequestHashLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/invites/"+inviteID+"/join-requests", r.URL.Path)
		writeRawTestJSON(t, w, protocol.SubmitNamespaceJoinRequestResponse{
			NamespaceID:     namespaceID,
			InviteID:        "not-an-invite-id",
			JoinRequestHash: joinRequestHash,
		})
	}))

	_, err := client.SubmitNamespaceJoinRequest(ctx, "token", namespaceID, inviteID, protocol.SubmitNamespaceJoinRequestRequest{})
	require.ErrorContains(t, err, "response invite")
}

func TestSubmitJoinRequestRejectsRequesterMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	inviteID := strings.Repeat("02", protocol.InviteIDLength)
	keyID := strings.Repeat("03", protocol.KeyIDLength)
	joinRequestHash := strings.Repeat("04", protocol.JoinRequestHashLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/invites/"+inviteID+"/join-requests", r.URL.Path)
		writeRawTestJSON(t, w, protocol.SubmitNamespaceJoinRequestResponse{
			NamespaceID:     namespaceID,
			InviteID:        inviteID,
			RequesterKind:   protocol.IdentityKindKeystore,
			RequesterKeyID:  strings.Repeat("05", protocol.KeyIDLength),
			JoinRequestHash: joinRequestHash,
			Status:          protocol.NamespaceJoinRequestStatusPending,
		})
	}))

	_, err := client.SubmitNamespaceJoinRequest(ctx, "token", namespaceID, inviteID, protocol.SubmitNamespaceJoinRequestRequest{
		JoinRequest: protocol.NamespaceJoinRequest{
			Kind:  protocol.IdentityKindKeystore,
			KeyID: keyID,
		},
	})
	require.ErrorContains(t, err, "key mismatch")
}

func TestRevokeNamespaceInviteRejectsFalseRevoked(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	inviteID := strings.Repeat("02", protocol.InviteIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/invites/"+inviteID, r.URL.Path)
		writeRawTestJSON(t, w, protocol.RevokeNamespaceInviteResponse{
			NamespaceID: namespaceID,
			InviteID:    inviteID,
			Revoked:     false,
		})
	}))

	_, err := client.RevokeNamespaceInvite(ctx, "token", namespaceID, inviteID)
	require.ErrorContains(t, err, "must report revoked")
}

func TestRejectNamespaceJoinRequestRejectsFalseRejected(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	keyID := strings.Repeat("02", protocol.KeyIDLength)
	joinRequestHash := strings.Repeat("03", protocol.JoinRequestHashLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/join-requests/"+keyID+"/"+joinRequestHash, r.URL.Path)
		writeRawTestJSON(t, w, protocol.RejectNamespaceJoinRequestResponse{
			NamespaceID:     namespaceID,
			RequesterKeyID:  keyID,
			JoinRequestHash: joinRequestHash,
			Rejected:        false,
		})
	}))

	_, err := client.RejectNamespaceJoinRequest(ctx, "token", namespaceID, keyID, joinRequestHash)
	require.ErrorContains(t, err, "must report rejected")
}

func TestApproveJoinRequestRejectsKeyMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	keyID := strings.Repeat("02", protocol.KeyIDLength)
	otherKeyID := strings.Repeat("03", protocol.KeyIDLength)
	joinRequestHash := strings.Repeat("04", protocol.JoinRequestHashLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/join-requests/"+keyID+"/"+joinRequestHash+"/approve", r.URL.Path)
		writeRawTestJSON(t, w, protocol.ApproveNamespaceJoinRequestResponse{
			NamespaceID:     namespaceID,
			MemberKeyID:     otherKeyID,
			JoinRequestHash: joinRequestHash,
		})
	}))

	_, err := client.ApproveNamespaceJoinRequest(ctx, "token", namespaceID, keyID, joinRequestHash, protocol.ApproveNamespaceJoinRequestRequest{})
	require.ErrorContains(t, err, "key mismatch")
}

func TestGetWrappedDEKRejectsCoordinateMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	keyID := strings.Repeat("02", protocol.KeyIDLength)
	otherKeyID := strings.Repeat("03", protocol.KeyIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/namespaces/"+namespaceID+"/wrapped-deks/"+keyID, r.URL.Path)
		writeRawTestJSON(t, w, protocol.GetWrappedDEKResponse{
			NamespaceID: namespaceID,
			KeyID:       otherKeyID,
		})
	}))

	_, err := client.GetWrappedDEK(ctx, "token", namespaceID, keyID)
	require.ErrorContains(t, err, "key mismatch")
}

func TestGetItemRejectsCoordinateMismatch(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	itemID := strings.Repeat("02", protocol.ItemIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/kv/"+namespaceID+"/"+itemID, r.URL.Path)
		writeRawTestJSON(t, w, protocol.GetItemResponse{
			NamespaceID: namespaceID,
			ItemID:      strings.Repeat("03", protocol.ItemIDLength),
			Version:     1,
		})
	}))

	_, err := client.GetItem(ctx, "token", namespaceID, itemID)
	require.ErrorContains(t, err, "item mismatch")
}

func TestPutItemRejectsUnexpectedVersion(t *testing.T) {
	ctx := context.Background()
	namespaceID := strings.Repeat("01", protocol.NamespaceIDLength)
	itemID := strings.Repeat("02", protocol.ItemIDLength)
	client := newRawTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/kv/"+namespaceID+"/"+itemID, r.URL.Path)
		writeRawTestJSON(t, w, protocol.PutItemResponse{
			NamespaceID: namespaceID,
			ItemID:      itemID,
			Version:     2,
		})
	}))

	_, err := client.PutItem(ctx, "token", namespaceID, itemID, protocol.PutItemRequest{}, nil)
	require.ErrorContains(t, err, "version mismatch")
}

func newRawTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(server.URL, server.Client())
	require.NoError(t, err)
	return client
}

func writeRawTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(value))
}
