// Package auth provides API-key hashing/verification, tenant-context propagation
// through context.Context, and the row-level-security guard used by every
// tenant-scoped code path.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// APIKeyPrefix is prepended to all issued keys for easy identification.
const APIKeyPrefix = "ksk"

// Argon2 parameters. Tuned for an interactive control-plane verification path:
// strong enough to resist offline cracking, fast enough for per-request use
// behind a small cache.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

var (
	// ErrMalformedKey indicates the presented key is not in the expected
	// "ksk_<id>_<secret>" form.
	ErrMalformedKey = errors.New("auth: malformed api key")
	// ErrMalformedHash indicates a stored hash that cannot be decoded.
	ErrMalformedHash = errors.New("auth: malformed argon2 hash")
)

// GeneratedAPIKey is a freshly minted key. The plaintext is returned exactly
// once at creation; only KeyID and Hash are persisted.
type GeneratedAPIKey struct {
	// Plaintext is the full key to hand to the caller: ksk_<id>_<secret>.
	Plaintext string
	// KeyID is the public, indexable identifier (stored in the api_keys row).
	KeyID string
	// Hash is the argon2id encoded hash of the secret (stored, never logged).
	Hash string
}

// GenerateAPIKey mints a new API key with a random id and secret and returns the
// plaintext plus the persisted fields.
func GenerateAPIKey() (GeneratedAPIKey, error) {
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return GeneratedAPIKey{}, fmt.Errorf("rand id: %w", err)
	}
	secretBytes := make([]byte, 24)
	if _, err := rand.Read(secretBytes); err != nil {
		return GeneratedAPIKey{}, fmt.Errorf("rand secret: %w", err)
	}
	keyID := hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	hash, err := HashSecret(secret)
	if err != nil {
		return GeneratedAPIKey{}, err
	}
	return GeneratedAPIKey{
		Plaintext: fmt.Sprintf("%s_%s_%s", APIKeyPrefix, keyID, secret),
		KeyID:     keyID,
		Hash:      hash,
	}, nil
}

// HashSecret hashes a secret with argon2id and returns the encoded representation
// "$argon2id$v=19$m=...,t=...,p=...$salt$hash".
func HashSecret(secret string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("rand salt: %w", err)
	}
	digest := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// VerifySecret reports whether secret matches the argon2id encodedHash using a
// constant-time comparison.
func VerifySecret(secret, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrMalformedHash
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrMalformedHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrMalformedHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrMalformedHash
	}
	got := argon2.IDKey([]byte(secret), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ParseAPIKey splits a presented key into its key id and secret components.
func ParseAPIKey(key string) (keyID, secret string, err error) {
	parts := strings.SplitN(key, "_", 3)
	if len(parts) != 3 || parts[0] != APIKeyPrefix || parts[1] == "" || parts[2] == "" {
		return "", "", ErrMalformedKey
	}
	return parts[1], parts[2], nil
}
