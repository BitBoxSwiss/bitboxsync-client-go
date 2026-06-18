// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeLowerHexExactRejectsUppercase(t *testing.T) {
	_, err := DecodeLowerHexExact("keyId", strings.Repeat("a", KeyIDLength*2), KeyIDLength)
	require.NoError(t, err)
	_, err = DecodeLowerHexExact("keyId", "A"+strings.Repeat("a", KeyIDLength*2-1), KeyIDLength)
	require.Error(t, err)
}

func TestDecodeHexExactAllowsGenericUppercaseHex(t *testing.T) {
	raw, err := DecodeHexExact("signature", "AB", 1)
	require.NoError(t, err)
	require.Equal(t, byte(0xab), raw[0])
}

func TestDecodeBase64RejectsNonCanonicalEncoding(t *testing.T) {
	raw, err := DecodeBase64("value", base64.StdEncoding.EncodeToString([]byte{1, 2}))
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, raw)

	_, err = DecodeBase64("value", base64.StdEncoding.EncodeToString([]byte{1, 2})+"\n")
	require.ErrorContains(t, err, "canonical base64")
}

func TestJoinRequestHash(t *testing.T) {
	payload := []byte("join-request")
	want := sha256.Sum256(payload)
	require.Equal(t, want[:], JoinRequestHash(payload))
}

func TestServerOriginHashRequiresCanonicalOrigin(t *testing.T) {
	hash, err := ServerOriginHash("https://sync.example")
	require.NoError(t, err)
	want := sha256.Sum256([]byte("https://sync.example"))
	require.Equal(t, want[:], hash)

	_, err = ServerOriginHash("https://sync.example:443")
	require.ErrorContains(t, err, "canonical")

	_, err = ServerOriginHash("https://sync.example:0443")
	require.ErrorContains(t, err, "canonical")
}

func TestCanonicalServerOriginRejectsTooLongOrigin(t *testing.T) {
	host := strings.Repeat("a", MaxServerOriginLength-len("https://"))
	_, err := CanonicalServerOrigin("https://" + host)
	require.NoError(t, err)

	host = strings.Repeat("a", MaxServerOriginLength-len("https://")+1)
	_, err = CanonicalServerOrigin("https://" + host)
	require.ErrorContains(t, err, "maximum")
}

func TestCanonicalServerOriginRejectsNonASCIIDomain(t *testing.T) {
	_, err := CanonicalServerOrigin("https://b\u00fccher.example")
	require.ErrorContains(t, err, "lowercase ASCII")

	_, err = CanonicalServerOrigin("https://bad-.example")
	require.ErrorContains(t, err, "IDNA A-label")
}

func TestValidateIdentifiersRejectUppercaseHex(t *testing.T) {
	require.Error(t, ValidateNamespaceID("A"+strings.Repeat("a", NamespaceIDLength*2-1)))
	require.Error(t, ValidateKeyID("A"+strings.Repeat("a", KeyIDLength*2-1)))
	require.Error(t, ValidateItemID("A"+strings.Repeat("a", ItemIDLength*2-1)))
}

func TestParseIfMatchRequiresCanonicalQuotedETag(t *testing.T) {
	version, hasVersion, err := ParseIfMatch("")
	require.NoError(t, err)
	require.False(t, hasVersion)
	require.Zero(t, version)

	version, hasVersion, err = ParseIfMatch(QuoteETag(3))
	require.NoError(t, err)
	require.True(t, hasVersion)
	require.Equal(t, uint64(3), version)

	for _, value := range []string{
		"3",
		`""3""`,
		`"03"`,
		`"3" `,
		` "3"`,
		`"3", "4"`,
	} {
		_, hasVersion, err = ParseIfMatch(value)
		require.True(t, hasVersion, value)
		require.Error(t, err, value)
	}
}

func TestParsePublicKeysRejectUppercaseHex(t *testing.T) {
	_, err := ParseEd25519PublicKeyHex("authPublicKey", "A"+strings.Repeat("a", ed25519.PublicKeySize*2-1))
	require.Error(t, err)
	_, err = ParseX25519PublicKeyHex("wrapPublicKey", "A"+strings.Repeat("a", 32*2-1))
	require.Error(t, err)
}

func TestDecryptItemRejectsBadNonceLength(t *testing.T) {
	namespaceDEK := make([]byte, NamespaceDEKLen)
	require.NotPanics(t, func() {
		_, err := DecryptItem(namespaceDEK, []byte("short"), nil, make([]byte, 16))
		require.Error(t, err)
	})
}

func TestNamespaceInviteTokenRoundTrip(t *testing.T) {
	inviteSecret := EncodeBase64URL(make([]byte, InviteSecretLength))
	token := NamespaceInviteToken{
		Version:      NamespaceJoinRequestVersion,
		ServerOrigin: "https://sync.example:443",
		NamespaceID:  hex.EncodeToString(make([]byte, NamespaceIDLength)),
		InviteID:     hex.EncodeToString(make([]byte, InviteIDLength)),
		ExpiresAt:    1735689600,
		InviteSecret: inviteSecret,
	}

	encoded, err := EncodeNamespaceInviteToken(token)
	require.NoError(t, err)
	require.Equal(t, "bitboxsync://join-namespace?v=1&s=sync.example&n="+token.NamespaceID+
		"&i="+token.InviteID+"&e=1735689600#k="+inviteSecret, encoded)

	parsed, err := ParseNamespaceInviteToken(encoded)
	require.NoError(t, err)
	require.Equal(t, NamespaceInviteToken{
		Version:      NamespaceJoinRequestVersion,
		ServerOrigin: "https://sync.example",
		NamespaceID:  token.NamespaceID,
		InviteID:     token.InviteID,
		ExpiresAt:    token.ExpiresAt,
		InviteSecret: inviteSecret,
	}, parsed)
}

func TestNamespaceInviteTokenAcceptsDocumentedQueryOrder(t *testing.T) {
	inviteSecret := EncodeBase64URL(make([]byte, InviteSecretLength))
	namespaceID := strings.Repeat("0", NamespaceIDLength*2)
	inviteID := strings.Repeat("1", InviteIDLength*2)
	value := "bitboxsync://join-namespace?v=1&s=sync.example&n=" +
		namespaceID + "&i=" + inviteID + "&e=1735689600#k=" + inviteSecret

	parsed, err := ParseNamespaceInviteToken(value)
	require.NoError(t, err)
	require.Equal(t, NamespaceInviteToken{
		Version:      NamespaceJoinRequestVersion,
		ServerOrigin: "https://sync.example",
		NamespaceID:  namespaceID,
		InviteID:     inviteID,
		ExpiresAt:    1735689600,
		InviteSecret: inviteSecret,
	}, parsed)
}

func TestNamespaceInviteTokenRejectsPaddedSecret(t *testing.T) {
	_, err := ParseNamespaceInviteToken("bitboxsync://join-namespace?e=1735689600&i=" +
		strings.Repeat("0", InviteIDLength*2) + "&n=" + strings.Repeat("0", NamespaceIDLength*2) +
		"&s=sync.example&v=1#k=" + strings.Repeat("a", 43) + "=")
	require.ErrorContains(t, err, "unpadded base64url")
}

func TestNamespaceInviteTokenRejectsNonCanonicalURI(t *testing.T) {
	token := NamespaceInviteToken{
		Version:      NamespaceJoinRequestVersion,
		ServerOrigin: "https://sync.example",
		NamespaceID:  strings.Repeat("0", NamespaceIDLength*2),
		InviteID:     strings.Repeat("1", InviteIDLength*2),
		ExpiresAt:    1735689600,
		InviteSecret: EncodeBase64URL(make([]byte, InviteSecretLength)),
	}
	encoded, err := EncodeNamespaceInviteToken(token)
	require.NoError(t, err)

	cases := map[string]string{
		strings.Replace(encoded, "s=sync.example", "s=sync.example:443", 1):        "canonical",
		strings.Replace(encoded, "#k=", "&extra=1#k=", 1):                          "canonical",
		strings.Replace(encoded, "#k=", "&i="+token.InviteID+"#k=", 1):             "canonical",
		strings.Replace(encoded, "e=1735689600", "e=01735689600", 1):               "canonical",
		strings.Replace(encoded, token.InviteSecret, token.InviteSecret+"&x=1", 1): "canonical",
		strings.Replace(encoded, "#k=", "&v=%zz#k=", 1):                            "parse invite query",
		strings.Replace(encoded, "&i=", "&&i=", 1):                                 "empty query",
		strings.Replace(encoded, token.InviteSecret, token.InviteSecret+"&&", 1):   "empty fragment",
		strings.Replace(encoded, "bitboxsync:", "BitBoxSync:", 1):                  "unsupported",
	}
	for value, wantErr := range cases {
		_, err := ParseNamespaceInviteToken(value)
		require.ErrorContains(t, err, wantErr)
	}
}
