// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	IdentityKindKeystore = "keystore"

	NamespaceKindDefault = "default"
	NamespaceKindShared  = "shared"

	SpamControlKindNone        = "none"
	SpamControlKindAttestation = "attestation"

	ChallengePurposeLogin           = "login"
	ChallengePurposeRefresh         = "refresh"
	ChallengePurposeSensitiveAction = "sensitive-action"

	SensitiveActionRevokeAllTokens       = "revoke-all-tokens"
	SensitiveActionCreateNamespaceInvite = "create-namespace-invite"
	NamespaceJoinRequestStatusPending    = "pending"
	NamespaceJoinRequestVersion          = 1
	MaxActiveInvitesPerNamespace         = 5
	MaxPendingJoinRequestsPerInvite      = 20
	MaxAcceptedJoinRequestsPerInvite     = 10
	MaxPendingJoinRequestsPerRequester   = 20
	MaxInviteTTL                         = time.Hour
	DefaultInviteTTL                     = 10 * time.Minute
	MaxJoinRequestTTL                    = 10 * time.Minute

	KeyIDLength                   = 32
	NamespaceIDLength             = 16
	InviteIDLength                = 16
	InviteSecretLength            = 32
	InviteServerSecretLength      = 32
	InviteServerSecretHashLength  = 32
	InviteProofLength             = 32
	JoinRequestHashLength         = 32
	ServerOriginHashLength        = 32
	MaxServerOriginLength         = 128
	ItemIDLength                  = 32
	NamespaceDEKLen               = 32
	ItemNonceLength               = chacha20poly1305.NonceSizeX
	MaxItemCiphertextSize         = 64 * 1024
	MaxItemsPerNamespace          = 10000
	MaxNamespacesPerKey           = 32
	MaxMembersPerNamespace        = 32
	MaxActiveTokensPerKey         = 32
	MaxKeysPerDevice              = 100
	MaxNamespacesCreatedPerDevice = 100
	MaxNamespaceStoredBytes       = 64 * 1024 * 1024
	WrappedDEKLenV1               = 1 + 32 + NamespaceIDLength + NamespaceDEKLen + 16

	namespaceBlobKeyInfo   = "bitboxsync-namespace-blob-aead-v1"
	namespaceItemKeyInfo   = "bitboxsync-namespace-item-id-v1"
	wrapDEKInfo            = "bitboxsync-wrap-dek-v1"
	itemAADPrefix          = "bitboxsync-item-aad"
	intentPrefix           = "bitboxsync-intent"
	joinRequestPrefix      = "bitboxsync-join-request"
	inviteServerSecretInfo = "bitboxsync-invite-server-secret-v1"
	inviteProofKeyInfo     = "bitboxsync-invite-proof-key-v1"
	wrappedDEKVersion      = 0x01
	intentVersion          = 0x01
	joinRequestVersion     = 0x01
)

var (
	ErrInvalidKind        = errors.New("invalid kind")
	ErrInvalidNamespaceID = errors.New("invalid namespace id")
	ErrInvalidKeyID       = errors.New("invalid key id")
	ErrInvalidItemID      = errors.New("invalid item id")
	ErrAADMismatch        = errors.New("aad mismatch")
	ErrNamespaceMismatch  = errors.New("namespace mismatch")
	ErrInvalidWrappedDEK  = errors.New("invalid wrapped dek")
	ErrKeyIDMismatch      = errors.New("key id does not match auth public key")
	ErrUnsupportedVersion = errors.New("unsupported version")
)

// KeyIDFromAuthPublicKey derives the canonical key ID from an auth public key.
func KeyIDFromAuthPublicKey(authPublicKey ed25519.PublicKey) [KeyIDLength]byte {
	return sha256.Sum256(authPublicKey)
}

// VerifyKeyIDMatchesAuthPublicKey checks that the supplied key ID matches the
// hash of the auth public key.
func VerifyKeyIDMatchesAuthPublicKey(keyIDHex string, authPublicKey ed25519.PublicKey) error {
	keyID, err := DecodeLowerHexExact("keyId", keyIDHex, KeyIDLength)
	if err != nil {
		return err
	}
	sum := KeyIDFromAuthPublicKey(authPublicKey)
	if !bytes.Equal(sum[:], keyID) {
		return ErrKeyIDMismatch
	}
	return nil
}

// EncodeEd25519PublicKey returns the hex encoding used on the wire for an
// Ed25519 public key.
func EncodeEd25519PublicKey(authPublicKey ed25519.PublicKey) string {
	return hex.EncodeToString(authPublicKey)
}

// ParseEd25519PublicKeyHex decodes a lowercase-hex Ed25519 public key into the
// standard library key type.
func ParseEd25519PublicKeyHex(name, value string) (ed25519.PublicKey, error) {
	authPublicKey, err := DecodeLowerHexExact(name, value, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(authPublicKey), nil
}

// EncodeX25519PublicKey returns the hex encoding used on the wire for an
// X25519 public key.
func EncodeX25519PublicKey(wrapPublicKey *ecdh.PublicKey) string {
	return hex.EncodeToString(wrapPublicKey.Bytes())
}

// ParseX25519PublicKeyHex decodes a lowercase-hex X25519 public key into the
// standard library key type.
func ParseX25519PublicKeyHex(name, value string) (*ecdh.PublicKey, error) {
	wrapPublicKey, err := DecodeLowerHexExact(name, value, 32)
	if err != nil {
		return nil, err
	}
	parsed, err := ecdh.X25519().NewPublicKey(wrapPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	return parsed, nil
}

// RandomNamespaceID returns a freshly generated random namespace ID.
func RandomNamespaceID() ([]byte, error) {
	out := make([]byte, NamespaceIDLength)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("generate namespace id: %w", err)
	}
	return out, nil
}

// RandomInviteID returns a freshly generated public invite ID.
func RandomInviteID() ([]byte, error) {
	out := make([]byte, InviteIDLength)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("generate invite id: %w", err)
	}
	return out, nil
}

// RandomInviteSecret returns a freshly generated QR invite secret.
func RandomInviteSecret() ([]byte, error) {
	out := make([]byte, InviteSecretLength)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("generate invite secret: %w", err)
	}
	return out, nil
}

// RandomNamespaceDEK returns a freshly generated namespace DEK.
func RandomNamespaceDEK() ([]byte, error) {
	out := make([]byte, NamespaceDEKLen)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("generate namespace dek: %w", err)
	}
	return out, nil
}

// NamespaceBlobKey derives the AEAD key used to encrypt item payloads for a
// namespace.
func NamespaceBlobKey(namespaceDEK []byte) ([]byte, error) {
	if len(namespaceDEK) != NamespaceDEKLen {
		return nil, fmt.Errorf("namespace dek must be %d bytes", NamespaceDEKLen)
	}
	key, err := hkdf.Key(sha256.New, namespaceDEK, nil, namespaceBlobKeyInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive namespace blob key: %w", err)
	}
	return key, nil
}

// NamespaceMapKey derives the HMAC key used to map logical keys to opaque item
// IDs.
func NamespaceMapKey(namespaceDEK []byte) ([]byte, error) {
	if len(namespaceDEK) != NamespaceDEKLen {
		return nil, fmt.Errorf("namespace dek must be %d bytes", NamespaceDEKLen)
	}
	key, err := hkdf.Key(sha256.New, namespaceDEK, nil, namespaceItemKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive namespace map key: %w", err)
	}
	return key, nil
}

// ItemID derives the opaque item ID for a logical key within a namespace.
func ItemID(namespaceDEK []byte, logicalKey string) (string, error) {
	mapKey, err := NamespaceMapKey(namespaceDEK)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, mapKey)
	if _, err := mac.Write([]byte(logicalKey)); err != nil {
		return "", fmt.Errorf("map logical key: %w", err)
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// BuildItemAAD constructs the canonical AAD for an item using hex-encoded IDs.
func BuildItemAAD(namespaceIDHex, itemIDHex string, version uint64) ([]byte, error) {
	namespaceID, err := DecodeLowerHexExact("namespaceId", namespaceIDHex, NamespaceIDLength)
	if err != nil {
		return nil, err
	}
	itemID, err := DecodeLowerHexExact("itemId", itemIDHex, ItemIDLength)
	if err != nil {
		return nil, err
	}
	return BuildItemAADFromBytes(namespaceID, itemID, version), nil
}

// BuildItemAADFromBytes constructs the canonical AAD for an item using binary
// IDs.
func BuildItemAADFromBytes(namespaceID, itemID []byte, version uint64) []byte {
	buf := make([]byte, 0, len(itemAADPrefix)+1+len(namespaceID)+len(itemID)+8)
	buf = append(buf, itemAADPrefix...)
	buf = append(buf, 0x01)
	buf = append(buf, namespaceID...)
	buf = append(buf, itemID...)
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, version)
	buf = append(buf, versionBytes...)
	return buf
}

// EncryptItem encrypts one item payload and returns the nonce, AAD, and
// ciphertext to send to the server.
func EncryptItem(namespaceIDHex, itemIDHex string, version uint64, namespaceDEK, plaintext []byte) (nonce, aad, ciphertext []byte, err error) {
	aad, err = BuildItemAAD(namespaceIDHex, itemIDHex, version)
	if err != nil {
		return nil, nil, nil, err
	}
	blobKey, err := NamespaceBlobKey(namespaceDEK)
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := chacha20poly1305.NewX(blobKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("construct item aead: %w", err)
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generate item nonce: %w", err)
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return nonce, aad, ciphertext, nil
}

// DecryptItem decrypts one encrypted item payload.
func DecryptItem(namespaceDEK, nonce, aad, ciphertext []byte) ([]byte, error) {
	if len(nonce) != ItemNonceLength {
		return nil, fmt.Errorf("nonce must be %d bytes", ItemNonceLength)
	}
	blobKey, err := NamespaceBlobKey(namespaceDEK)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(blobKey)
	if err != nil {
		return nil, fmt.Errorf("construct item aead: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt item: %w", err)
	}
	return plaintext, nil
}

// WrapNamespaceDEK HPKE-wraps a namespace DEK for one recipient and binds it to
// the namespace ID.
func WrapNamespaceDEK(recipientWrapPublicKey *ecdh.PublicKey, namespaceID, namespaceDEK []byte) ([]byte, error) {
	if len(namespaceID) != NamespaceIDLength {
		return nil, ErrInvalidNamespaceID
	}
	if len(namespaceDEK) != NamespaceDEKLen {
		return nil, fmt.Errorf("namespace dek must be %d bytes", NamespaceDEKLen)
	}
	hpkePub, err := hpke.NewDHKEMPublicKey(recipientWrapPublicKey)
	if err != nil {
		return nil, fmt.Errorf("construct hpke public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(hpkePub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(wrapDEKInfo))
	if err != nil {
		return nil, fmt.Errorf("construct hpke sender: %w", err)
	}
	plaintext := append(clone(namespaceID), namespaceDEK...)
	ciphertext, err := sender.Seal(nil, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal wrapped dek: %w", err)
	}
	out := make([]byte, 1+len(enc)+len(ciphertext))
	out[0] = wrappedDEKVersion
	copy(out[1:], enc)
	copy(out[1+len(enc):], ciphertext)
	return out, nil
}

// WrappedDEKLengthForVersion returns the exact raw wrapped-DEK length expected
// for one wrapped-DEK wire-format version byte.
func WrappedDEKLengthForVersion(version byte) (int, error) {
	switch version {
	case wrappedDEKVersion:
		return WrappedDEKLenV1, nil
	default:
		return 0, ErrUnsupportedVersion
	}
}

// ValidateWrappedDEK checks that a wrapped DEK uses a supported version and
// has the exact raw length required by that version.
func ValidateWrappedDEK(wrappedDEK []byte) error {
	if len(wrappedDEK) == 0 {
		return ErrInvalidWrappedDEK
	}
	expectedLen, err := WrappedDEKLengthForVersion(wrappedDEK[0])
	if err != nil {
		return err
	}
	if len(wrappedDEK) != expectedLen {
		return ErrInvalidWrappedDEK
	}
	return nil
}

// UnwrapNamespaceDEK unwraps a wrapped namespace DEK and verifies its namespace
// binding.
func UnwrapNamespaceDEK(recipientWrapPrivateKey, expectedNamespaceID, wrappedDEK []byte) ([]byte, error) {
	if len(expectedNamespaceID) != NamespaceIDLength {
		return nil, ErrInvalidNamespaceID
	}
	if err := ValidateWrappedDEK(wrappedDEK); err != nil {
		return nil, err
	}
	enc := wrappedDEK[1:33]
	ciphertext := wrappedDEK[33:]
	recipientPriv, err := ecdh.X25519().NewPrivateKey(recipientWrapPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse wrap private key: %w", err)
	}
	hpkePriv, err := hpke.NewDHKEMPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("construct hpke private key: %w", err)
	}
	recipient, err := hpke.NewRecipient(enc, hpkePriv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(wrapDEKInfo))
	if err != nil {
		return nil, fmt.Errorf("construct hpke recipient: %w", err)
	}
	plaintext, err := recipient.Open(nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("open wrapped dek: %w", err)
	}
	if len(plaintext) != NamespaceIDLength+NamespaceDEKLen {
		return nil, ErrInvalidWrappedDEK
	}
	if !bytes.Equal(plaintext[:NamespaceIDLength], expectedNamespaceID) {
		return nil, ErrNamespaceMismatch
	}
	return clone(plaintext[NamespaceIDLength:]), nil
}

// LoginIntent builds the canonical byte payload that must be signed for login.
func LoginIntent(challenge []byte, kind string, keyID []byte, authPublicKey ed25519.PublicKey, wrapPublicKey *ecdh.PublicKey) ([]byte, error) {
	if len(challenge) != 32 {
		return nil, fmt.Errorf("challenge must be 32 bytes")
	}
	if len(keyID) != KeyIDLength {
		return nil, ErrInvalidKeyID
	}
	if len(authPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auth public key must be %d bytes", ed25519.PublicKeySize)
	}
	wrapPublicKeyBytes := wrapPublicKey.Bytes()
	if len(wrapPublicKeyBytes) != 32 {
		return nil, fmt.Errorf("wrap public key must be 32 bytes")
	}
	kindCode, err := kindCode(kind)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(intentPrefix)+1+1+len(challenge)+1+len(keyID)+len(authPublicKey)+len(wrapPublicKeyBytes))
	buf = append(buf, intentPrefix...)
	buf = append(buf, intentVersion, 0x01)
	buf = append(buf, challenge...)
	buf = append(buf, kindCode)
	buf = append(buf, keyID...)
	buf = append(buf, authPublicKey...)
	buf = append(buf, wrapPublicKeyBytes...)
	return buf, nil
}

// RefreshIntent builds the canonical byte payload that must be signed for token
// refresh.
func RefreshIntent(challenge []byte, kind string, keyID []byte) ([]byte, error) {
	if len(challenge) != 32 {
		return nil, fmt.Errorf("challenge must be 32 bytes")
	}
	if len(keyID) != KeyIDLength {
		return nil, ErrInvalidKeyID
	}
	kindCode, err := kindCode(kind)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(intentPrefix)+1+1+len(challenge)+1+len(keyID))
	buf = append(buf, intentPrefix...)
	buf = append(buf, intentVersion, 0x02)
	buf = append(buf, challenge...)
	buf = append(buf, kindCode)
	buf = append(buf, keyID...)
	return buf, nil
}

// SensitiveActionIntent builds the canonical byte payload that must be signed
// for a fresh sensitive action authorization.
func SensitiveActionIntent(challenge []byte, action, kind string, keyID, actionFields []byte) ([]byte, error) {
	if len(challenge) != 32 {
		return nil, fmt.Errorf("challenge must be 32 bytes")
	}
	if len(keyID) != KeyIDLength {
		return nil, ErrInvalidKeyID
	}
	actionCode, err := sensitiveActionCode(action)
	if err != nil {
		return nil, err
	}
	kindCode, err := kindCode(kind)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(intentPrefix)+1+1+1+len(challenge)+1+len(keyID)+len(actionFields))
	buf = append(buf, intentPrefix...)
	buf = append(buf, intentVersion, 0x03, actionCode)
	buf = append(buf, challenge...)
	buf = append(buf, kindCode)
	buf = append(buf, keyID...)
	buf = append(buf, actionFields...)
	return buf, nil
}

// CreateNamespaceInviteActionFields builds the canonical sensitive-action
// action fields for namespace invite creation.
func CreateNamespaceInviteActionFields(namespaceID, inviteID, inviteServerSecretHash []byte, expiresAt uint64, maxPending, maxAccepted uint32) ([]byte, error) {
	if len(namespaceID) != NamespaceIDLength {
		return nil, ErrInvalidNamespaceID
	}
	if len(inviteID) != InviteIDLength {
		return nil, fmt.Errorf("invite id must be %d bytes", InviteIDLength)
	}
	if len(inviteServerSecretHash) != InviteServerSecretHashLength {
		return nil, fmt.Errorf("invite server secret hash must be %d bytes", InviteServerSecretHashLength)
	}
	buf := make([]byte, 0, NamespaceIDLength+InviteIDLength+InviteServerSecretHashLength+8+4+4)
	buf = append(buf, namespaceID...)
	buf = append(buf, inviteID...)
	buf = append(buf, inviteServerSecretHash...)
	expiresBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresBytes, expiresAt)
	buf = append(buf, expiresBytes...)
	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, maxPending)
	buf = append(buf, countBytes...)
	binary.BigEndian.PutUint32(countBytes, maxAccepted)
	buf = append(buf, countBytes...)
	return buf, nil
}

// DeriveInviteServerSecret derives the server admission credential from the
// raw QR invite secret.
func DeriveInviteServerSecret(inviteSecret []byte) ([]byte, error) {
	if len(inviteSecret) != InviteSecretLength {
		return nil, fmt.Errorf("invite secret must be %d bytes", InviteSecretLength)
	}
	mac := hmac.New(sha256.New, inviteSecret)
	_, _ = mac.Write([]byte(inviteServerSecretInfo))
	return mac.Sum(nil), nil
}

// DeriveInviteProofKey derives the requester-to-approver proof key from the
// raw QR invite secret. This key must not be sent to the server.
func DeriveInviteProofKey(inviteSecret []byte) ([]byte, error) {
	if len(inviteSecret) != InviteSecretLength {
		return nil, fmt.Errorf("invite secret must be %d bytes", InviteSecretLength)
	}
	mac := hmac.New(sha256.New, inviteSecret)
	_, _ = mac.Write([]byte(inviteProofKeyInfo))
	return mac.Sum(nil), nil
}

// InviteProof computes the end-to-end proof that a join requester knew the raw
// QR invite secret.
func InviteProof(inviteSecret, joinRequestPayload []byte) ([]byte, error) {
	inviteProofKey, err := DeriveInviteProofKey(inviteSecret)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, inviteProofKey)
	_, _ = mac.Write(joinRequestPayload)
	return mac.Sum(nil), nil
}

// VerifyInviteProof verifies the HMAC proof against the raw QR invite secret.
func VerifyInviteProof(inviteSecret, joinRequestPayload, inviteProof []byte) error {
	if len(inviteProof) != InviteProofLength {
		return fmt.Errorf("invite proof must be %d bytes", InviteProofLength)
	}
	expected, err := InviteProof(inviteSecret, joinRequestPayload)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, inviteProof) {
		return errors.New("invalid invite proof")
	}
	return nil
}

// JoinRequestHash returns the stable identifier for one canonical join request
// payload.
func JoinRequestHash(joinRequestPayload []byte) []byte {
	hash := sha256.Sum256(joinRequestPayload)
	return hash[:]
}

// JoinRequestPayload builds the canonical byte payload signed by a prospective
// namespace member.
func JoinRequestPayload(kind string, namespaceID, inviteID, serverOriginHash, keyID []byte, authPublicKey ed25519.PublicKey, wrapPublicKey *ecdh.PublicKey, expiresAt uint64) ([]byte, error) {
	if len(namespaceID) != NamespaceIDLength {
		return nil, ErrInvalidNamespaceID
	}
	if len(inviteID) != InviteIDLength {
		return nil, fmt.Errorf("invite id must be %d bytes", InviteIDLength)
	}
	if len(serverOriginHash) != ServerOriginHashLength {
		return nil, fmt.Errorf("server origin hash must be %d bytes", ServerOriginHashLength)
	}
	if len(keyID) != KeyIDLength {
		return nil, ErrInvalidKeyID
	}
	if len(authPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auth public key must be %d bytes", ed25519.PublicKeySize)
	}
	wrapPublicKeyBytes := wrapPublicKey.Bytes()
	if len(wrapPublicKeyBytes) != 32 {
		return nil, fmt.Errorf("wrap public key must be 32 bytes")
	}
	kindCode, err := kindCode(kind)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(joinRequestPrefix)+1+NamespaceIDLength+InviteIDLength+ServerOriginHashLength+1+KeyIDLength+ed25519.PublicKeySize+32+8)
	buf = append(buf, joinRequestPrefix...)
	buf = append(buf, joinRequestVersion)
	buf = append(buf, namespaceID...)
	buf = append(buf, inviteID...)
	buf = append(buf, serverOriginHash...)
	buf = append(buf, kindCode)
	buf = append(buf, keyID...)
	buf = append(buf, authPublicKey...)
	buf = append(buf, wrapPublicKeyBytes...)
	expiresBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresBytes, expiresAt)
	buf = append(buf, expiresBytes...)
	return buf, nil
}

// CanonicalServerOrigin validates and canonicalizes a BitBoxSync server origin.
func CanonicalServerOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse server origin: %w", err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("server origin scheme must be https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("server origin must contain only scheme, host, and optional port")
	}
	host := parsed.Hostname()
	if host == "" || !isASCII(host) || strings.ToLower(host) != host {
		return "", fmt.Errorf("server origin host must be lowercase ASCII")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return "", fmt.Errorf("server origin host must be an IDNA A-label host")
	}
	for _, label := range strings.Split(host, ".") {
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("server origin host must be an IDNA A-label host")
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", fmt.Errorf("server origin host must be an IDNA A-label host")
			}
		}
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsedPort == 0 {
			return "", fmt.Errorf("server origin port must be canonical")
		}
		if strconv.FormatUint(parsedPort, 10) != port {
			return "", fmt.Errorf("server origin port must be canonical")
		}
		if parsedPort == 443 {
			port = ""
		}
	}
	canonical := parsed.Scheme + "://" + host
	if port != "" {
		canonical += ":" + port
	}
	if len(canonical) > MaxServerOriginLength {
		return "", fmt.Errorf("server origin exceeds maximum %d bytes", MaxServerOriginLength)
	}
	return canonical, nil
}

func isASCII(value string) bool {
	for _, ch := range value {
		if ch > 0x7f {
			return false
		}
	}
	return true
}

// ServerOriginHash returns the canonical join-request hash for a server origin.
func ServerOriginHash(origin string) ([]byte, error) {
	canonical, err := CanonicalServerOrigin(origin)
	if err != nil {
		return nil, err
	}
	if canonical != origin {
		return nil, fmt.Errorf("server origin must be canonical")
	}
	hash := sha256.Sum256([]byte(origin))
	return hash[:], nil
}

// EncodeNamespaceInviteToken encodes invite material into the canonical QR URI.
func EncodeNamespaceInviteToken(token NamespaceInviteToken) (string, error) {
	if token.Version != NamespaceJoinRequestVersion {
		return "", ErrUnsupportedVersion
	}
	serverOrigin, err := CanonicalServerOrigin(token.ServerOrigin)
	if err != nil {
		return "", err
	}
	if err := ValidateNamespaceID(token.NamespaceID); err != nil {
		return "", err
	}
	if err := ValidateInviteID(token.InviteID); err != nil {
		return "", err
	}
	if token.ExpiresAt <= 0 {
		return "", fmt.Errorf("invite expiry must be positive")
	}
	if _, err := DecodeBase64URLExact("inviteSecret", token.InviteSecret, InviteSecretLength); err != nil {
		return "", err
	}
	return "bitboxsync://join-namespace?v=" + strconv.Itoa(NamespaceJoinRequestVersion) +
		"&s=" + encodedServerOrigin(serverOrigin) +
		"&n=" + token.NamespaceID +
		"&i=" + token.InviteID +
		"&e=" + strconv.FormatInt(token.ExpiresAt, 10) +
		"#k=" + token.InviteSecret, nil
}

// ParseNamespaceInviteToken parses and validates the canonical QR invite URI.
func ParseNamespaceInviteToken(value string) (NamespaceInviteToken, error) {
	if !strings.HasPrefix(value, "bitboxsync:") {
		return NamespaceInviteToken{}, errors.New("unsupported namespace invite URI")
	}
	u, err := url.Parse(value)
	if err != nil {
		return NamespaceInviteToken{}, fmt.Errorf("parse namespace invite: %w", err)
	}
	if u.Scheme != "bitboxsync" || u.Host != "join-namespace" || u.Path != "" {
		return NamespaceInviteToken{}, errors.New("unsupported namespace invite URI")
	}
	if err := rejectEmptyInviteURIComponents("query", u.RawQuery); err != nil {
		return NamespaceInviteToken{}, err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return NamespaceInviteToken{}, fmt.Errorf("parse invite query: %w", err)
	}
	if !exactInviteURIFields(q, "v", "s", "n", "i", "e") {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must use canonical query fields")
	}
	version, ok := singleInviteURIValue(q, "v")
	if !ok {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must include one version")
	}
	if version != strconv.Itoa(NamespaceJoinRequestVersion) {
		return NamespaceInviteToken{}, ErrUnsupportedVersion
	}
	serverValue, ok := singleInviteURIValue(q, "s")
	if !ok {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must include one server origin")
	}
	serverOrigin, err := CanonicalServerOrigin("https://" + serverValue)
	if err != nil {
		return NamespaceInviteToken{}, err
	}
	if serverValue != encodedServerOrigin(serverOrigin) {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must use canonical server origin encoding")
	}
	namespaceID, ok := singleInviteURIValue(q, "n")
	if !ok {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must include one namespace id")
	}
	if err := ValidateNamespaceID(namespaceID); err != nil {
		return NamespaceInviteToken{}, err
	}
	inviteID, ok := singleInviteURIValue(q, "i")
	if !ok {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must include one invite id")
	}
	if err := ValidateInviteID(inviteID); err != nil {
		return NamespaceInviteToken{}, err
	}
	expiresValue, ok := singleInviteURIValue(q, "e")
	if !ok {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must include one expiry")
	}
	expiresAt, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil {
		return NamespaceInviteToken{}, fmt.Errorf("parse invite expiry: %w", err)
	}
	if expiresAt <= 0 {
		return NamespaceInviteToken{}, fmt.Errorf("invite expiry must be positive")
	}
	if expiresValue != strconv.FormatInt(expiresAt, 10) {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must use canonical expiry")
	}
	rawFragment := u.EscapedFragment()
	if err := rejectEmptyInviteURIComponents("fragment", rawFragment); err != nil {
		return NamespaceInviteToken{}, err
	}
	fragment, err := url.ParseQuery(rawFragment)
	if err != nil {
		return NamespaceInviteToken{}, fmt.Errorf("parse invite fragment: %w", err)
	}
	if !exactInviteURIFields(fragment, "k") {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must use canonical fragment fields")
	}
	inviteSecret, ok := singleInviteURIValue(fragment, "k")
	if !ok {
		return NamespaceInviteToken{}, errors.New("namespace invite URI must include one invite secret")
	}
	if _, err := DecodeBase64URLExact("inviteSecret", inviteSecret, InviteSecretLength); err != nil {
		return NamespaceInviteToken{}, err
	}
	token := NamespaceInviteToken{
		Version:      NamespaceJoinRequestVersion,
		ServerOrigin: serverOrigin,
		NamespaceID:  namespaceID,
		InviteID:     inviteID,
		ExpiresAt:    expiresAt,
		InviteSecret: inviteSecret,
	}
	return token, nil
}

func exactInviteURIFields(values url.Values, names ...string) bool {
	if len(values) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := singleInviteURIValue(values, name); !ok {
			return false
		}
	}
	return true
}

func encodedServerOrigin(canonical string) string {
	return strings.TrimPrefix(canonical, "https://")
}

func rejectEmptyInviteURIComponents(name, raw string) error {
	if raw == "" {
		return fmt.Errorf("namespace invite URI must include %s fields", name)
	}
	for _, component := range strings.Split(raw, "&") {
		if component == "" {
			return fmt.Errorf("namespace invite URI must not contain empty %s components", name)
		}
	}
	return nil
}

func singleInviteURIValue(values url.Values, name string) (string, bool) {
	items := values[name]
	if len(items) != 1 {
		return "", false
	}
	return items[0], true
}

// DecodeHexExact decodes a hex string and checks that it has the expected
// length.
func DecodeHexExact(name, value string, size int) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%s must be %d bytes", name, size)
	}
	return raw, nil
}

// DecodeLowerHexExact decodes a lowercase hex string and checks that it has the
// expected length.
func DecodeLowerHexExact(name, value string, size int) ([]byte, error) {
	if strings.ToLower(value) != value {
		return nil, fmt.Errorf("%s must be lowercase hex", name)
	}
	return DecodeHexExact(name, value, size)
}

// DecodeBase64 decodes a base64 string.
func DecodeBase64(name, value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	if base64.StdEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must use canonical base64", name)
	}
	return raw, nil
}

// DecodeBase64Exact decodes a base64 string and checks that it has the expected
// length.
func DecodeBase64Exact(name, value string, size int) ([]byte, error) {
	raw, err := DecodeBase64(name, value)
	if err != nil {
		return nil, err
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%s must be %d bytes", name, size)
	}
	return raw, nil
}

// DecodeBase64URLExact decodes an unpadded base64url string and checks that it
// has the expected length.
func DecodeBase64URLExact(name, value string, size int) ([]byte, error) {
	if strings.Contains(value, "=") {
		return nil, fmt.Errorf("%s must be unpadded base64url", name)
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%s must be %d bytes", name, size)
	}
	if base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must use canonical base64url", name)
	}
	return raw, nil
}

// EncodeBase64 encodes bytes with standard base64.
func EncodeBase64(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

// EncodeBase64URL encodes bytes with unpadded base64url.
func EncodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

// ValidateNamespaceID checks that value is a valid lowercase-hex namespace ID.
func ValidateNamespaceID(value string) error {
	_, err := DecodeLowerHexExact("namespaceId", value, NamespaceIDLength)
	return err
}

// ValidateInviteID checks that value is a valid lowercase-hex invite ID.
func ValidateInviteID(value string) error {
	_, err := DecodeLowerHexExact("inviteId", value, InviteIDLength)
	return err
}

// ValidateKeyID checks that value is a valid lowercase-hex key ID.
func ValidateKeyID(value string) error {
	_, err := DecodeLowerHexExact("keyId", value, KeyIDLength)
	return err
}

// ValidateJoinRequestHash checks that value is a valid lowercase-hex join
// request hash.
func ValidateJoinRequestHash(value string) error {
	_, err := DecodeLowerHexExact("joinRequestHash", value, JoinRequestHashLength)
	return err
}

// ValidateItemID checks that value is a valid lowercase-hex item ID.
func ValidateItemID(value string) error {
	_, err := DecodeLowerHexExact("itemId", value, ItemIDLength)
	return err
}

// QuoteETag formats an item version as a quoted ETag header value.
func QuoteETag(version uint64) string {
	return fmt.Sprintf("%q", strconv.FormatUint(version, 10))
}

// ParseIfMatch parses an HTTP If-Match version header.
func ParseIfMatch(value string) (uint64, bool, error) {
	if strings.TrimSpace(value) == "" {
		return 0, false, nil
	}
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, true, fmt.Errorf("If-Match must be a quoted decimal version")
	}
	unquoted := value[1 : len(value)-1]
	version, err := strconv.ParseUint(unquoted, 10, 64)
	if err != nil {
		return 0, true, fmt.Errorf("parse If-Match: %w", err)
	}
	if QuoteETag(version) != value {
		return 0, true, fmt.Errorf("If-Match must use canonical ETag encoding")
	}
	return version, true, nil
}

// VerifyAAD checks that aad matches the canonical AAD for the supplied item
// coordinates.
func VerifyAAD(namespaceIDHex, itemIDHex string, version uint64, aad []byte) error {
	expected, err := BuildItemAAD(namespaceIDHex, itemIDHex, version)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, aad) {
		return ErrAADMismatch
	}
	return nil
}

// kindCode returns the canonical single-byte encoding for an identity kind.
func kindCode(kind string) (byte, error) {
	switch kind {
	case IdentityKindKeystore:
		return 0x01, nil
	default:
		return 0, ErrInvalidKind
	}
}

// sensitiveActionCode returns the canonical single-byte encoding for a
// sensitive action.
func sensitiveActionCode(action string) (byte, error) {
	switch action {
	case SensitiveActionRevokeAllTokens:
		return 0x01, nil
	case SensitiveActionCreateNamespaceInvite:
		return 0x02, nil
	default:
		return 0, fmt.Errorf("unsupported sensitive action %q", action)
	}
}

// clone returns a copy of the byte slice.
func clone[T ~byte](in []T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	copy(out, in)
	return out
}
