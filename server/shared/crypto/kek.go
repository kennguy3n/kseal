package crypto

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

// TenantSealer seals and opens per-tenant secret material (signing-key private
// keys, webhook secrets). It abstracts over two key-management strategies:
//
//   - the platform key-encryption key (KEK) used for every tenant, and
//   - per-tenant customer-managed keys (BYOK/CMK) where the data-encryption key
//     (DEK) is wrapped by a customer-controlled cloud KMS.
//
// The strategy is chosen per call from the tenant's configuration, so a single
// deployment can serve plain-KEK tenants and CMK tenants side by side.
type TenantSealer interface {
	SealForTenant(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error)
	OpenForTenant(ctx context.Context, tenantID string, sealed []byte) ([]byte, error)
}

// SealForTenant seals plaintext under the platform KEK. The Encryptor is the
// default ("local KEK") TenantSealer implementation; tenantID is ignored
// because every tenant shares the platform KEK. Behavior and on-disk format are
// identical to Seal, so existing sealed material remains readable.
func (e *Encryptor) SealForTenant(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	return e.Seal(plaintext)
}

// OpenForTenant reverses SealForTenant using the platform KEK.
func (e *Encryptor) OpenForTenant(_ context.Context, _ string, sealed []byte) ([]byte, error) {
	return e.Open(sealed)
}

// KMSClient is the single external/third-party touch-point of the CMK feature:
// it wraps and unwraps a per-tenant data-encryption key (DEK) under a
// customer-managed key identified by keyURI. Implementations talk to a cloud
// KMS/HSM (AWS KMS, GCP KMS, Azure Key Vault, …). Tests inject an in-memory
// fake so no real cloud is contacted.
//
// kseal never sees the customer-managed key itself: it asks the KMS to wrap a
// freshly generated DEK and stores only the wrapped form, and later asks the
// KMS to unwrap it. This is standard envelope encryption.
type KMSClient interface {
	// Wrap encrypts plaintextDEK under the customer key keyURI.
	Wrap(ctx context.Context, keyURI string, plaintextDEK []byte) (wrappedDEK []byte, err error)
	// Unwrap decrypts wrappedDEK previously produced by Wrap for keyURI.
	Unwrap(ctx context.Context, keyURI string, wrappedDEK []byte) (plaintextDEK []byte, err error)
}

// TenantKMSResolver reports whether a tenant uses a customer-managed key and,
// if so, the key URI to wrap/unwrap its DEK under. enabled=false means the
// tenant falls back to the platform KEK.
type TenantKMSResolver interface {
	KMSKeyURI(ctx context.Context, tenantID string) (keyURI string, enabled bool, err error)
}

// dekSize is the length of the per-secret data-encryption key. 32 bytes feeds
// the same AES-256-GCM primitive the platform KEK uses.
const dekSize = 32

// CMK envelope framing. The header is self-describing so OpenForTenant can
// validate the layout and fail closed on anything unexpected.
var cmkMagic = [4]byte{'K', 'S', 'C', '1'} // kseal CMK envelope, v1

const cmkVersion byte = 1

// cmkHeaderLen is magic(4) + version(1) + wrappedLen(2).
const cmkHeaderLen = 4 + 1 + 2

// CMK errors. Unwrap/decrypt failures are surfaced (never swallowed) so callers
// fail closed and deny the operation rather than leaking to the platform KEK.
var (
	// ErrCMKDecrypt indicates the CMK envelope could not be opened (bad framing
	// or a DEK that does not match the ciphertext).
	ErrCMKDecrypt = errors.New("crypto: cmk envelope decrypt failed")
	// ErrNotCMKEnvelope indicates a CMK-enabled tenant has sealed material that
	// is not a CMK envelope (e.g. sealed under the platform KEK before CMK was
	// turned on). Re-seal by rotating the tenant's signing key.
	ErrNotCMKEnvelope = errors.New("crypto: expected cmk envelope")
	// ErrCMKDisabled indicates a tenant whose CMK is now disabled still has
	// CMK-sealed material. The open is denied (fail closed); re-enable the
	// tenant's KMS key to read it, or rotate its signing key under the platform
	// KEK. Returned instead of an opaque AES-GCM failure for diagnosability.
	ErrCMKDisabled = errors.New("crypto: cmk-sealed material but cmk is disabled for tenant")
)

// CMKKeyManager is the customer-managed-key TenantSealer. CMK-enabled tenants
// get per-tenant DEKs wrapped by their own KMS key; all other tenants fall back
// to the platform KEK transparently. It fails closed: if a tenant is CMK
// enabled and the KMS wrap/unwrap fails, the operation is denied — it never
// silently falls back to the platform KEK.
type CMKKeyManager struct {
	platform *Encryptor
	kms      KMSClient
	resolver TenantKMSResolver
}

// NewCMKKeyManager builds a CMKKeyManager. platform is the fallback encryptor
// for non-CMK tenants, kms wraps/unwraps customer DEKs, and resolver decides
// per tenant which path applies.
func NewCMKKeyManager(platform *Encryptor, kms KMSClient, resolver TenantKMSResolver) (*CMKKeyManager, error) {
	if platform == nil {
		return nil, errors.New("crypto: nil platform encryptor")
	}
	if kms == nil {
		return nil, errors.New("crypto: nil kms client")
	}
	if resolver == nil {
		return nil, errors.New("crypto: nil tenant kms resolver")
	}
	return &CMKKeyManager{platform: platform, kms: kms, resolver: resolver}, nil
}

// SealForTenant seals plaintext under the tenant's customer-managed key when one
// is configured, otherwise under the platform KEK.
func (m *CMKKeyManager) SealForTenant(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error) {
	keyURI, enabled, err := m.resolver.KMSKeyURI(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant cmk: %w", err)
	}
	if !enabled {
		return m.platform.Seal(plaintext)
	}

	dek, err := RandomBytes(dekSize)
	if err != nil {
		return nil, err
	}
	defer zero(dek)

	dekEnc, err := NewEncryptor(dek)
	if err != nil {
		return nil, err
	}
	ciphertext, err := dekEnc.Seal(plaintext)
	if err != nil {
		return nil, err
	}
	wrapped, err := m.kms.Wrap(ctx, keyURI, dek)
	if err != nil {
		// Fail closed: do not persist material we cannot later unwrap.
		return nil, fmt.Errorf("kms wrap: %w", err)
	}
	return encodeCMKEnvelope(wrapped, ciphertext)
}

// OpenForTenant reverses SealForTenant. For CMK tenants it unwraps the DEK via
// the KMS and fails closed on any error instead of falling back to the platform
// KEK.
func (m *CMKKeyManager) OpenForTenant(ctx context.Context, tenantID string, sealed []byte) ([]byte, error) {
	keyURI, enabled, err := m.resolver.KMSKeyURI(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant cmk: %w", err)
	}
	if !enabled {
		if hasCMKMagic(sealed) {
			// Tenant was CMK-enabled when this was sealed but is no longer.
			// Surface a diagnostic error rather than an opaque AES-GCM failure.
			return nil, ErrCMKDisabled
		}
		return m.platform.Open(sealed)
	}

	wrapped, ciphertext, err := decodeCMKEnvelope(sealed)
	if err != nil {
		return nil, err
	}
	dek, err := m.kms.Unwrap(ctx, keyURI, wrapped)
	if err != nil {
		// Fail closed: deny rather than reaching for the platform KEK.
		return nil, fmt.Errorf("kms unwrap: %w", err)
	}
	defer zero(dek)
	if len(dek) != dekSize {
		return nil, fmt.Errorf("%w: unwrapped dek is %d bytes", ErrCMKDecrypt, len(dek))
	}
	dekEnc, err := NewEncryptor(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := dekEnc.Open(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCMKDecrypt, err)
	}
	return plaintext, nil
}

// encodeCMKEnvelope frames a wrapped DEK and DEK-encrypted ciphertext.
func encodeCMKEnvelope(wrappedDEK, ciphertext []byte) ([]byte, error) {
	if len(wrappedDEK) == 0 {
		return nil, errors.New("crypto: empty wrapped dek")
	}
	if len(wrappedDEK) > 0xFFFF {
		return nil, fmt.Errorf("crypto: wrapped dek too large: %d bytes", len(wrappedDEK))
	}
	out := make([]byte, 0, cmkHeaderLen+len(wrappedDEK)+len(ciphertext))
	out = append(out, cmkMagic[:]...)
	out = append(out, cmkVersion)
	var lp [2]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(wrappedDEK)))
	out = append(out, lp[:]...)
	out = append(out, wrappedDEK...)
	out = append(out, ciphertext...)
	return out, nil
}

// hasCMKMagic reports whether b begins with the CMK envelope magic, identifying
// CMK-sealed material without fully decoding it.
func hasCMKMagic(b []byte) bool {
	return len(b) >= len(cmkMagic) && [4]byte(b[:4]) == cmkMagic
}

// decodeCMKEnvelope parses a CMK envelope, validating magic and version and
// bounds-checking the wrapped-DEK length.
func decodeCMKEnvelope(b []byte) (wrappedDEK, ciphertext []byte, err error) {
	if len(b) < cmkHeaderLen {
		return nil, nil, ErrNotCMKEnvelope
	}
	if !hasCMKMagic(b) {
		return nil, nil, ErrNotCMKEnvelope
	}
	if b[4] != cmkVersion {
		return nil, nil, fmt.Errorf("%w: unknown version %d", ErrNotCMKEnvelope, b[4])
	}
	wrappedLen := int(binary.BigEndian.Uint16(b[5:7]))
	if len(b) < cmkHeaderLen+wrappedLen {
		return nil, nil, fmt.Errorf("%w: truncated wrapped dek", ErrCMKDecrypt)
	}
	wrappedDEK = b[cmkHeaderLen : cmkHeaderLen+wrappedLen]
	ciphertext = b[cmkHeaderLen+wrappedLen:]
	if len(ciphertext) == 0 {
		return nil, nil, fmt.Errorf("%w: empty ciphertext", ErrCMKDecrypt)
	}
	return wrappedDEK, ciphertext, nil
}

// zero overwrites b so DEK material does not linger in memory longer than
// necessary.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
