// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"context"
	"crypto/ecdh"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
)

func (e *Engine) signLoginIntent(ctx context.Context, challenge []byte) ([]byte, error) {
	return e.identity.SignLoginIntent(ctx, challenge)
}

func (e *Engine) signRefreshIntent(ctx context.Context, challenge []byte) ([]byte, error) {
	return e.identity.SignRefreshIntent(ctx, challenge)
}

func (e *Engine) signRevokeAllTokensIntent(ctx context.Context, challenge []byte) ([]byte, error) {
	return e.identity.SignRevokeAllTokensIntent(ctx, challenge)
}

func (e *Engine) signCreateNamespaceInviteIntent(ctx context.Context, challenge, namespaceID, inviteID, inviteServerSecretHash []byte, expiresAt int64, maxAccepted int) ([]byte, error) {
	return e.identity.SignCreateNamespaceInviteIntent(ctx, challenge, namespaceID, inviteID, inviteServerSecretHash, expiresAt, maxAccepted)
}

func (e *Engine) signNamespaceJoinRequestIntent(ctx context.Context, namespaceID, inviteID []byte, serverOrigin string, expiresAt int64) ([]byte, error) {
	return e.identity.SignNamespaceJoinRequestIntent(ctx, namespaceID, inviteID, serverOrigin, expiresAt)
}

func wrapNamespaceDEKFor(namespaceID string, namespaceDEK []byte, recipientWrapPublicKey *ecdh.PublicKey) ([]byte, error) {
	namespaceIDRaw, err := protocol.DecodeLowerHexExact("namespaceId", namespaceID, protocol.NamespaceIDLength)
	if err != nil {
		return nil, err
	}
	return protocol.WrapNamespaceDEK(recipientWrapPublicKey, namespaceIDRaw, namespaceDEK)
}

func (e *Engine) unwrapNamespaceDEK(ctx context.Context, namespaceID string, wrappedDEK []byte) ([]byte, error) {
	namespaceIDRaw, err := protocol.DecodeLowerHexExact("namespaceId", namespaceID, protocol.NamespaceIDLength)
	if err != nil {
		return nil, err
	}
	return e.identity.UnwrapNamespaceDEK(ctx, namespaceIDRaw, wrappedDEK)
}
