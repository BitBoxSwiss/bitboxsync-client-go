// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
)

// Client is a thin HTTP wrapper around the BitBoxSync API.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
}

// APIError represents a non-2xx JSON error response from the server.
type APIError struct {
	// StatusCode is the HTTP status code returned by the server.
	StatusCode int
	// Message is the parsed JSON error string, when one was returned.
	Message string
}

type jsonRequest struct {
	method         string
	path           string
	accessToken    string
	request        any
	requestHeaders http.Header
	response       any
}

// Error returns a human-readable description of an API error response.
func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("bitboxsync api error: status=%d", e.StatusCode)
	}
	return fmt.Sprintf("bitboxsync api error: status=%d message=%s", e.StatusCode, e.Message)
}

// New constructs a raw BitBoxSync API client for baseURL.
func New(baseURL string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 75 * time.Second}
	}
	return &Client{
		baseURL:    parsed,
		httpClient: httpClient,
	}, nil
}

// BaseURL returns the configured API base URL.
func (c *Client) BaseURL() string {
	return c.baseURL.String()
}

// Challenge requests a fresh authentication challenge for the given purpose.
func (c *Client) Challenge(ctx context.Context, purpose string) (*protocol.ChallengeResponse, error) {
	var resp protocol.ChallengeResponse
	if err := c.doJSON(ctx, jsonRequest{
		method: http.MethodPost,
		path:   "/v1/auth/challenge",
		request: protocol.ChallengeRequest{
			Purpose: purpose,
			Kind:    protocol.IdentityKindKeystore,
		},
		response: &resp,
	}); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SensitiveActionChallenge requests a challenge bound to one sensitive action
// and canonical action-fields hash.
func (c *Client) SensitiveActionChallenge(ctx context.Context, action, actionFieldsHash string) (*protocol.ChallengeResponse, error) {
	var resp protocol.ChallengeResponse
	if err := c.doJSON(ctx, jsonRequest{
		method: http.MethodPost,
		path:   "/v1/auth/challenge",
		request: protocol.ChallengeRequest{
			Purpose:          protocol.ChallengePurposeSensitiveAction,
			Kind:             protocol.IdentityKindKeystore,
			Action:           action,
			ActionFieldsHash: actionFieldsHash,
		},
		response: &resp,
	}); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Login exchanges a signed login request for a bearer token.
func (c *Client) Login(ctx context.Context, req protocol.LoginRequest) (*protocol.LoginResponse, error) {
	var resp protocol.LoginResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:   http.MethodPost,
		path:     "/v1/auth/login",
		request:  req,
		response: &resp,
	}); err != nil {
		return nil, err
	}
	if resp.Kind != req.Kind {
		return nil, fmt.Errorf("login response kind mismatch: got %q want %q", resp.Kind, req.Kind)
	}
	if resp.DefaultNamespaceID != nil {
		if err := protocol.ValidateNamespaceID(*resp.DefaultNamespaceID); err != nil {
			return nil, fmt.Errorf("login response default namespace: %w", err)
		}
	}
	return &resp, nil
}

// Refresh exchanges a signed refresh request for a fresh bearer token.
func (c *Client) Refresh(ctx context.Context, accessToken string, req protocol.RefreshRequest) (*protocol.RefreshResponse, error) {
	var resp protocol.RefreshResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodPost,
		path:        "/v1/auth/refresh",
		accessToken: accessToken,
		request:     req,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.Kind != req.Kind {
		return nil, fmt.Errorf("refresh response kind mismatch: got %q want %q", resp.Kind, req.Kind)
	}
	return &resp, nil
}

// RevokeAllTokens revokes all bearer tokens for the authenticated identity.
func (c *Client) RevokeAllTokens(ctx context.Context, accessToken string, req protocol.RevokeAllTokensRequest) error {
	return c.doJSON(ctx, jsonRequest{
		method:      http.MethodDelete,
		path:        "/v1/auth/tokens",
		accessToken: accessToken,
		request:     req,
	})
}

// GetDefaultNamespace returns the default namespace for the authenticated
// identity.
func (c *Client) GetDefaultNamespace(ctx context.Context, accessToken string) (*protocol.DefaultNamespaceResponse, error) {
	var resp protocol.DefaultNamespaceResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodGet,
		path:        "/v1/namespaces/default",
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if err := validateNamespaceResponse("default namespace response", resp.NamespaceID, resp.Kind, protocol.NamespaceKindDefault); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EnsureDefaultNamespace creates or returns the authenticated identity's
// default namespace.
func (c *Client) EnsureDefaultNamespace(ctx context.Context, accessToken string, req protocol.EnsureDefaultNamespaceRequest) (*protocol.EnsureDefaultNamespaceResponse, error) {
	if err := protocol.ValidateNamespaceID(req.ProposedNamespaceID); err != nil {
		return nil, err
	}
	var resp protocol.EnsureDefaultNamespaceResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodPut,
		path:        "/v1/namespaces/default",
		accessToken: accessToken,
		request:     req,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if err := validateNamespaceResponse("ensure default namespace response", resp.NamespaceID, resp.Kind, protocol.NamespaceKindDefault); err != nil {
		return nil, err
	}
	if resp.Created && resp.NamespaceID != req.ProposedNamespaceID {
		return nil, fmt.Errorf("ensure default namespace response namespace mismatch: got %q want %q", resp.NamespaceID, req.ProposedNamespaceID)
	}
	return &resp, nil
}

// ListNamespaces lists all namespaces visible to the authenticated identity.
func (c *Client) ListNamespaces(ctx context.Context, accessToken string) (*protocol.ListNamespacesResponse, error) {
	var resp protocol.ListNamespacesResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodGet,
		path:        "/v1/namespaces/mine",
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	return &resp, nil
}

// WatchNamespaces waits until one of the authenticated identity's visible
// namespaces differs from req.KnownHeads, or until the server-side wait times
// out. The returned namespaces are advisory invalidation hints; clients must
// still reconcile through the normal namespace and item endpoints.
func (c *Client) WatchNamespaces(ctx context.Context, accessToken string, req protocol.WatchNamespacesRequest) (*protocol.WatchNamespacesResponse, error) {
	for namespaceID := range req.KnownHeads {
		if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
			return nil, err
		}
	}
	var resp protocol.WatchNamespacesResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodPost,
		path:        "/v1/namespaces/watch",
		accessToken: accessToken,
		request:     req,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateSharedNamespace creates a shared namespace owned by the authenticated
// identity.
func (c *Client) CreateSharedNamespace(ctx context.Context, accessToken string, req protocol.CreateSharedNamespaceRequest) (*protocol.CreateSharedNamespaceResponse, error) {
	if err := protocol.ValidateNamespaceID(req.NamespaceID); err != nil {
		return nil, err
	}
	var resp protocol.CreateSharedNamespaceResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodPost,
		path:        "/v1/namespaces",
		accessToken: accessToken,
		request:     req,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if err := validateNamespaceResponse("create shared namespace response", resp.NamespaceID, resp.Kind, protocol.NamespaceKindShared); err != nil {
		return nil, err
	}
	if resp.NamespaceID != req.NamespaceID {
		return nil, fmt.Errorf("create shared namespace response namespace mismatch: got %q want %q", resp.NamespaceID, req.NamespaceID)
	}
	return &resp, nil
}

// GetMembers lists the members of a namespace.
func (c *Client) GetMembers(ctx context.Context, accessToken, namespaceID string) (*protocol.GetNamespaceMembersResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	var resp protocol.GetNamespaceMembersResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodGet,
		path:        "/v1/namespaces/" + namespaceID + "/members",
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("members response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	return &resp, nil
}

// CreateNamespaceInvite creates a short-lived invite for a shared namespace.
func (c *Client) CreateNamespaceInvite(ctx context.Context, accessToken, namespaceID string, req protocol.CreateNamespaceInviteRequest) (*protocol.CreateNamespaceInviteResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateInviteID(req.InviteID); err != nil {
		return nil, err
	}
	var resp protocol.CreateNamespaceInviteResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodPost,
		path:        "/v1/namespaces/" + namespaceID + "/invites",
		accessToken: accessToken,
		request:     req,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("create invite response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	if resp.InviteID != req.InviteID {
		return nil, fmt.Errorf("create invite response invite mismatch: got %q want %q", resp.InviteID, req.InviteID)
	}
	return &resp, nil
}

// ListNamespaceInvites lists active and recently revoked namespace invites.
func (c *Client) ListNamespaceInvites(ctx context.Context, accessToken, namespaceID string) (*protocol.ListNamespaceInvitesResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	var resp protocol.ListNamespaceInvitesResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodGet,
		path:        "/v1/namespaces/" + namespaceID + "/invites",
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("list invites response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	return &resp, nil
}

// RevokeNamespaceInvite revokes one namespace invite.
func (c *Client) RevokeNamespaceInvite(ctx context.Context, accessToken, namespaceID, inviteID string) (*protocol.RevokeNamespaceInviteResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateInviteID(inviteID); err != nil {
		return nil, err
	}
	var resp protocol.RevokeNamespaceInviteResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodDelete,
		path:        "/v1/namespaces/" + namespaceID + "/invites/" + inviteID,
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("revoke invite response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	if resp.InviteID != inviteID {
		return nil, fmt.Errorf("revoke invite response invite mismatch: got %q want %q", resp.InviteID, inviteID)
	}
	if !resp.Revoked {
		return nil, fmt.Errorf("revoke invite response must report revoked")
	}
	return &resp, nil
}

// SubmitNamespaceJoinRequest submits a signed join request through an invite.
func (c *Client) SubmitNamespaceJoinRequest(ctx context.Context, accessToken, namespaceID, inviteID string, req protocol.SubmitNamespaceJoinRequestRequest) (*protocol.SubmitNamespaceJoinRequestResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateInviteID(inviteID); err != nil {
		return nil, err
	}
	var resp protocol.SubmitNamespaceJoinRequestResponse
	path := "/v1/namespaces/" + namespaceID + "/invites/" + inviteID + "/join-requests"
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodPost,
		path:        path,
		accessToken: accessToken,
		request:     req,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("submit join request response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	if err := protocol.ValidateInviteID(resp.InviteID); err != nil {
		return nil, fmt.Errorf("submit join request response invite: %w", err)
	}
	if err := protocol.ValidateJoinRequestHash(resp.JoinRequestHash); err != nil {
		return nil, fmt.Errorf("submit join request response hash: %w", err)
	}
	if resp.RequesterKind != req.JoinRequest.Kind {
		return nil, fmt.Errorf("submit join request response kind mismatch: got %q want %q", resp.RequesterKind, req.JoinRequest.Kind)
	}
	if resp.RequesterKeyID != req.JoinRequest.KeyID {
		return nil, fmt.Errorf("submit join request response key mismatch: got %q want %q", resp.RequesterKeyID, req.JoinRequest.KeyID)
	}
	if resp.Status != protocol.NamespaceJoinRequestStatusPending {
		return nil, fmt.Errorf("submit join request response status mismatch: got %q want %q", resp.Status, protocol.NamespaceJoinRequestStatusPending)
	}
	return &resp, nil
}

// ListNamespaceJoinRequests lists pending join requests for a namespace.
func (c *Client) ListNamespaceJoinRequests(ctx context.Context, accessToken, namespaceID string) (*protocol.ListNamespaceJoinRequestsResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	var resp protocol.ListNamespaceJoinRequestsResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodGet,
		path:        "/v1/namespaces/" + namespaceID + "/join-requests",
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("list join requests response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	return &resp, nil
}

// ApproveNamespaceJoinRequest approves one pending join request.
func (c *Client) ApproveNamespaceJoinRequest(ctx context.Context, accessToken, namespaceID, keyID, joinRequestHash string, req protocol.ApproveNamespaceJoinRequestRequest) (*protocol.ApproveNamespaceJoinRequestResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateKeyID(keyID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateJoinRequestHash(joinRequestHash); err != nil {
		return nil, err
	}
	var resp protocol.ApproveNamespaceJoinRequestResponse
	path := "/v1/namespaces/" + namespaceID + "/join-requests/" + keyID + "/" + joinRequestHash + "/approve"
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodPut,
		path:        path,
		accessToken: accessToken,
		request:     req,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("approve join request response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	if resp.MemberKeyID != keyID {
		return nil, fmt.Errorf("approve join request response key mismatch: got %q want %q", resp.MemberKeyID, keyID)
	}
	if resp.JoinRequestHash != joinRequestHash {
		return nil, fmt.Errorf("approve join request response hash mismatch: got %q want %q", resp.JoinRequestHash, joinRequestHash)
	}
	return &resp, nil
}

// RejectNamespaceJoinRequest rejects one pending join request.
func (c *Client) RejectNamespaceJoinRequest(ctx context.Context, accessToken, namespaceID, keyID, joinRequestHash string) (*protocol.RejectNamespaceJoinRequestResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateKeyID(keyID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateJoinRequestHash(joinRequestHash); err != nil {
		return nil, err
	}
	var resp protocol.RejectNamespaceJoinRequestResponse
	path := "/v1/namespaces/" + namespaceID + "/join-requests/" + keyID + "/" + joinRequestHash
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodDelete,
		path:        path,
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("reject join request response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	if resp.RequesterKeyID != keyID {
		return nil, fmt.Errorf("reject join request response key mismatch: got %q want %q", resp.RequesterKeyID, keyID)
	}
	if resp.JoinRequestHash != joinRequestHash {
		return nil, fmt.Errorf("reject join request response hash mismatch: got %q want %q", resp.JoinRequestHash, joinRequestHash)
	}
	if !resp.Rejected {
		return nil, fmt.Errorf("reject join request response must report rejected")
	}
	return &resp, nil
}

// GetWrappedDEK fetches the wrapped namespace DEK for one member.
func (c *Client) GetWrappedDEK(ctx context.Context, accessToken, namespaceID, keyID string) (*protocol.GetWrappedDEKResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateKeyID(keyID); err != nil {
		return nil, err
	}
	var resp protocol.GetWrappedDEKResponse
	path := "/v1/namespaces/" + namespaceID + "/wrapped-deks/" + keyID
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodGet,
		path:        path,
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("wrapped dek response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	if resp.KeyID != keyID {
		return nil, fmt.Errorf("wrapped dek response key mismatch: got %q want %q", resp.KeyID, keyID)
	}
	return &resp, nil
}

// GetNamespaceItems returns the authoritative item/version snapshot for a
// namespace.
func (c *Client) GetNamespaceItems(ctx context.Context, accessToken, namespaceID string) (*protocol.GetNamespaceItemsResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	var resp protocol.GetNamespaceItemsResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodGet,
		path:        "/v1/namespaces/" + namespaceID + "/items",
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("namespace items response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	return &resp, nil
}

// GetItem fetches one encrypted item by namespace and item ID.
func (c *Client) GetItem(ctx context.Context, accessToken, namespaceID, itemID string) (*protocol.GetItemResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateItemID(itemID); err != nil {
		return nil, err
	}
	var resp protocol.GetItemResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:      http.MethodGet,
		path:        "/v1/kv/" + namespaceID + "/" + itemID,
		accessToken: accessToken,
		response:    &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("item response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	if resp.ItemID != itemID {
		return nil, fmt.Errorf("item response item mismatch: got %q want %q", resp.ItemID, itemID)
	}
	return &resp, nil
}

// PutItem creates or updates one encrypted item, optionally guarded by an
// If-Match version precondition.
func (c *Client) PutItem(ctx context.Context, accessToken, namespaceID, itemID string, req protocol.PutItemRequest, ifMatch *uint64) (*protocol.PutItemResponse, error) {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return nil, err
	}
	if err := protocol.ValidateItemID(itemID); err != nil {
		return nil, err
	}
	requestHeaders := make(http.Header)
	if ifMatch != nil {
		requestHeaders.Set("If-Match", protocol.QuoteETag(*ifMatch))
	}
	var resp protocol.PutItemResponse
	if err := c.doJSON(ctx, jsonRequest{
		method:         http.MethodPut,
		path:           "/v1/kv/" + namespaceID + "/" + itemID,
		accessToken:    accessToken,
		request:        req,
		requestHeaders: requestHeaders,
		response:       &resp,
	}); err != nil {
		return nil, err
	}
	if resp.NamespaceID != namespaceID {
		return nil, fmt.Errorf("put item response namespace mismatch: got %q want %q", resp.NamespaceID, namespaceID)
	}
	if resp.ItemID != itemID {
		return nil, fmt.Errorf("put item response item mismatch: got %q want %q", resp.ItemID, itemID)
	}
	expectedVersion := uint64(1)
	if ifMatch != nil {
		expectedVersion = *ifMatch + 1
	}
	if resp.Version != expectedVersion {
		return nil, fmt.Errorf("put item response version mismatch: got %d want %d", resp.Version, expectedVersion)
	}
	return &resp, nil
}

// doJSON performs one JSON-based HTTP request against the BitBoxSync API.
func (c *Client) doJSON(ctx context.Context, jsonReq jsonRequest) (err error) {
	var body io.Reader
	if jsonReq.request != nil {
		payload, err := json.Marshal(jsonReq.request)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(payload)
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(c.baseURL.Path, "/") + jsonReq.path

	req, err := http.NewRequestWithContext(ctx, jsonReq.method, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if jsonReq.request != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if jsonReq.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+jsonReq.accessToken)
	}
	for key, values := range jsonReq.requestHeaders {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform request: %w", err)
	}
	defer func() {
		if closeErr := httpResp.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close response body: %w", closeErr)
		}
	}()

	if httpResp.StatusCode >= 400 {
		var apiErr struct {
			Error string `json:"error"`
		}
		messageBytes, _ := io.ReadAll(httpResp.Body)
		if len(messageBytes) > 0 {
			_ = json.Unmarshal(messageBytes, &apiErr)
			if apiErr.Error == "" {
				apiErr.Error = strings.TrimSpace(string(messageBytes))
			}
		}
		return &APIError{StatusCode: httpResp.StatusCode, Message: apiErr.Error}
	}
	if jsonReq.response == nil {
		if _, err := io.Copy(io.Discard, httpResp.Body); err != nil {
			return fmt.Errorf("discard response body: %w", err)
		}
		return nil
	}
	if err := json.NewDecoder(httpResp.Body).Decode(jsonReq.response); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func validateNamespaceResponse(label, namespaceID, kind, wantKind string) error {
	if err := protocol.ValidateNamespaceID(namespaceID); err != nil {
		return fmt.Errorf("%s namespace: %w", label, err)
	}
	if kind != wantKind {
		return fmt.Errorf("%s kind mismatch: got %q want %q", label, kind, wantKind)
	}
	return nil
}
