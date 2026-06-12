// Package crypto provides the small set of cryptographic primitives the kseal
// server relies on: Ed25519 signing keys (config signing + trust tokens),
// HMAC-SHA256 (request proofs + webhook signing), cryptographically random
// nonces, and AES-256-GCM envelope encryption for protecting private key
// material at rest.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// NonceSize is the length in bytes of the nonces issued by the trust service.
const NonceSize = 32

// Ed25519KeyPair is a generated signing key pair.
type Ed25519KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateEd25519 creates a fresh Ed25519 key pair using crypto/rand.
func GenerateEd25519() (Ed25519KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ed25519KeyPair{}, fmt.Errorf("generate ed25519: %w", err)
	}
	return Ed25519KeyPair{Public: pub, Private: priv}, nil
}

// SignEd25519 signs message with priv.
func SignEd25519(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// VerifyEd25519 reports whether sig is a valid signature of message by pub.
func VerifyEd25519(pub ed25519.PublicKey, message, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}

// HMACSHA256 computes an HMAC-SHA256 tag over message with key.
func HMACSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// VerifyHMACSHA256 reports whether tag is the correct HMAC-SHA256 of message,
// using a constant-time comparison.
func VerifyHMACSHA256(key, message, tag []byte) bool {
	expected := HMACSHA256(key, message)
	return hmac.Equal(expected, tag)
}

// RandomNonce returns NonceSize bytes from crypto/rand.
func RandomNonce() ([]byte, error) {
	return RandomBytes(NonceSize)
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	return b, nil
}

// ConstantTimeEqual compares two byte slices in constant time.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ErrInvalidKEK indicates a key-encryption key of the wrong length.
var ErrInvalidKEK = errors.New("crypto: key-encryption key must be 32 bytes")

// Encryptor seals and opens private key material with AES-256-GCM using a
// 32-byte key-encryption key (KEK). It implements an envelope-encryption
// boundary; in production the KEK is provided by a KMS/HSM (future work).
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor builds an Encryptor from a 32-byte KEK.
func NewEncryptor(kek []byte) (*Encryptor, error) {
	if len(kek) != 32 {
		return nil, ErrInvalidKEK
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return &Encryptor{aead: aead}, nil
}

// Seal encrypts plaintext, prefixing the random nonce. The returned slice is
// nonce||ciphertext||tag.
func (e *Encryptor) Seal(plaintext []byte) ([]byte, error) {
	nonce, err := RandomBytes(e.aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal.
func (e *Encryptor) Open(sealed []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("crypto: sealed value too short")
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	plaintext, err := e.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return plaintext, nil
}

// SealString seals plaintext and returns a base64 (std) string.
func (e *Encryptor) SealString(plaintext []byte) (string, error) {
	sealed, err := e.Seal(plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenString reverses SealString.
func (e *Encryptor) OpenString(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	return e.Open(raw)
}
