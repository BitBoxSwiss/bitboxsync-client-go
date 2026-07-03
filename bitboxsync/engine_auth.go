// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/BitBoxSwiss/bitboxsync-client-go/raw"
)

// Identity returns a snapshot of the current persisted identity state.
func (e *Engine) Identity() IdentityState {
	return e.identityStateSnapshot()
}

// Login refreshes the identity's authenticated setup and wakes background
// retry loops that may have backed off while auth was unavailable.
func (e *Engine) Login(ctx context.Context) error {
	if err := e.runAuthenticated(ctx, func() error {
		_, err := e.defaultNamespace(ctx)
		return err
	}); err != nil {
		return err
	}
	signal(e.loginSucceededRun)
	signal(e.loginSucceededWatch)
	return nil
}

// RevokeAllTokens revokes all server-side bearer tokens for the current
// identity and clears the local access token.
func (e *Engine) RevokeAllTokens(ctx context.Context) error {
	return e.runAuthenticated(ctx, func() error {
		state := e.identityStateSnapshot()
		actionFieldsHash := sha256.Sum256(nil)
		challengeResp, err := e.client.SensitiveActionChallenge(
			ctx,
			protocol.SensitiveActionRevokeAllTokens,
			hex.EncodeToString(actionFieldsHash[:]),
		)
		if err != nil {
			return err
		}
		if challengeResp.SpamControl.Kind != protocol.SpamControlKindNone {
			return fmt.Errorf("unsupported spam control kind %q for token revocation", challengeResp.SpamControl.Kind)
		}
		challenge, err := protocol.DecodeBase64Exact("challenge", challengeResp.Challenge, 32)
		if err != nil {
			return err
		}
		signature, err := e.signRevokeAllTokensIntent(ctx, challenge)
		if err != nil {
			return err
		}
		req := protocol.RevokeAllTokensRequest{
			Kind:            e.identity.Kind(),
			KeyID:           e.keyID,
			Challenge:       challengeResp.Challenge,
			IntentSignature: hex.EncodeToString(signature),
		}
		if err := e.client.RevokeAllTokens(ctx, state.AccessToken, req); err != nil {
			return err
		}
		state.AccessToken = ""
		state.TokenExpiry = time.Time{}
		state.UpdatedAt = time.Now().UTC()
		if err := e.saveIdentityState(ctx, state); err != nil {
			return err
		}
		e.emitAuthEvent(EventAuthLoginRequired, state.TokenExpiry)
		return nil
	})
}

// ensureAuthenticated refreshes or recreates the bearer token when needed.
func (e *Engine) ensureAuthenticated(ctx context.Context) error {
	e.authMu.Lock()
	defer e.authMu.Unlock()

	state := e.identityStateSnapshot()
	now := time.Now().UTC()
	switch {
	case state.AccessToken == "":
		if err := e.login(ctx); err != nil {
			e.emitAuthEvent(EventAuthLoginRequired, state.TokenExpiry)
			return err
		}
	case state.TokenExpiry.Before(now):
		if err := e.login(ctx); err != nil {
			e.emitAuthEvent(EventAuthLoginRequired, state.TokenExpiry)
			return err
		}
	case state.TokenExpiry.Before(now.Add(e.cfg.RefreshSkew)):
		e.emitAuthEvent(EventAuthRefreshRecommended, state.TokenExpiry)
		// Refresh inside the skew window is proactive only. The current token is
		// still locally valid, so a temporary refresh failure should not prevent
		// sync from using it. If the server rejects it anyway, runAuthenticated's
		// 401 retry path clears the stale token, logs in, and retries once.
		_ = e.refresh(ctx)
	}
	return nil
}

// runAuthenticated runs fn with a usable bearer token. If the server rejects
// the token even though it is locally believed to be valid, the engine clears
// that stale token, logs in again, and retries fn once.
func (e *Engine) runAuthenticated(ctx context.Context, fn func() error) error {
	if err := e.ensureAuthenticated(ctx); err != nil {
		return err
	}
	failedToken := e.identityStateSnapshot().AccessToken
	if err := fn(); err != nil {
		if !isUnauthorizedAPIError(err) {
			return err
		}
		if err := e.reauthenticateAfterUnauthorized(ctx, failedToken); err != nil {
			return err
		}
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

// reauthenticateAfterUnauthorized replaces a server-rejected bearer token with
// a fresh login token. If another goroutine already moved the identity state to
// a different token, that newer token is left intact and the caller can simply
// retry with the current snapshot.
func (e *Engine) reauthenticateAfterUnauthorized(ctx context.Context, failedToken string) error {
	e.authMu.Lock()
	defer e.authMu.Unlock()

	state := e.identityStateSnapshot()
	if failedToken != "" && state.AccessToken != "" && state.AccessToken != failedToken {
		return nil
	}
	state.AccessToken = ""
	state.TokenExpiry = time.Time{}
	state.UpdatedAt = time.Now().UTC()
	if err := e.saveIdentityState(ctx, state); err != nil {
		return err
	}
	if err := e.login(ctx); err != nil {
		e.emitAuthEvent(EventAuthLoginRequired, state.TokenExpiry)
		return err
	}
	return nil
}

func isUnauthorizedAPIError(err error) bool {
	var apiErr *raw.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 401
}

// login performs a challenge/response login and stores the resulting bearer
// token.
func (e *Engine) login(ctx context.Context) error {
	challengeResp, err := e.client.Challenge(ctx, protocol.ChallengePurposeLogin)
	if err != nil {
		return err
	}
	challenge, err := protocol.DecodeBase64Exact("challenge", challengeResp.Challenge, 32)
	if err != nil {
		return err
	}
	signature, err := e.signLoginIntent(ctx, challenge)
	if err != nil {
		return err
	}
	authPublicKey := e.identity.AuthPublicKey()
	wrapPublicKey := e.identity.WrapPublicKey()
	loginReq := protocol.LoginRequest{
		Kind:            e.identity.Kind(),
		KeyID:           e.keyID,
		AuthPublicKey:   protocol.EncodeEd25519PublicKey(authPublicKey),
		WrapPublicKey:   protocol.EncodeX25519PublicKey(wrapPublicKey),
		Challenge:       challengeResp.Challenge,
		IntentSignature: hex.EncodeToString(signature),
	}
	if challengeResp.SpamControl.Kind == protocol.SpamControlKindAttestation {
		attestation, err := e.identity.Attest(ctx, challenge)
		if err != nil {
			return err
		}
		loginReq.Attestation = protocol.EncodeBase64(attestation)
	}
	loginResp, err := e.client.Login(ctx, loginReq)
	if err != nil {
		return err
	}

	state := IdentityState{
		KeyID:       e.keyID,
		Kind:        loginResp.Kind,
		AccessToken: loginResp.AccessToken,
		TokenExpiry: loginResp.ExpiresAt,
		UpdatedAt:   time.Now().UTC(),
	}
	if loginResp.DefaultNamespaceID != nil {
		state.DefaultNamespaceID = *loginResp.DefaultNamespaceID
	}
	if err := e.saveIdentityState(ctx, state); err != nil {
		return err
	}
	e.emitAuthEvent(EventAuthSessionReady, state.TokenExpiry)
	return nil
}

// refresh performs a challenge/response refresh using the current bearer token.
func (e *Engine) refresh(ctx context.Context) error {
	state := e.identityStateSnapshot()
	challengeResp, err := e.client.Challenge(ctx, protocol.ChallengePurposeRefresh)
	if err != nil {
		return err
	}
	challenge, err := protocol.DecodeBase64Exact("challenge", challengeResp.Challenge, 32)
	if err != nil {
		return err
	}
	signature, err := e.signRefreshIntent(ctx, challenge)
	if err != nil {
		return err
	}
	refreshReq := protocol.RefreshRequest{
		Kind:            e.identity.Kind(),
		KeyID:           e.keyID,
		Challenge:       challengeResp.Challenge,
		IntentSignature: hex.EncodeToString(signature),
	}
	if challengeResp.SpamControl.Kind == protocol.SpamControlKindAttestation {
		attestation, err := e.identity.Attest(ctx, challenge)
		if err != nil {
			return err
		}
		refreshReq.Attestation = protocol.EncodeBase64(attestation)
	}
	refreshResp, err := e.client.Refresh(ctx, state.AccessToken, refreshReq)
	if err != nil {
		return err
	}

	state.AccessToken = refreshResp.AccessToken
	state.TokenExpiry = refreshResp.ExpiresAt
	state.UpdatedAt = time.Now().UTC()
	if err := e.saveIdentityState(ctx, state); err != nil {
		return err
	}
	e.emitAuthEvent(EventAuthSessionReady, state.TokenExpiry)
	return nil
}

func (e *Engine) emitAuthEvent(eventType EventType, tokenExpiresAt time.Time) {
	e.emit(Event{
		Type:           eventType,
		TokenExpiresAt: tokenExpiresAt,
	})
}

func signal(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// saveIdentityState persists identity state and updates the in-memory snapshot.
func (e *Engine) saveIdentityState(ctx context.Context, state IdentityState) error {
	if state.KeyID == "" {
		state.KeyID = e.keyID
	}
	if state.Kind == "" {
		state.Kind = e.identity.Kind()
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	if err := e.store.SaveIdentity(ctx, state); err != nil {
		return err
	}
	e.mu.Lock()
	e.identityState = state
	e.mu.Unlock()
	return nil
}

// identityStateSnapshot returns a thread-safe copy of the current identity
// state.
func (e *Engine) identityStateSnapshot() IdentityState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.identityState
}
