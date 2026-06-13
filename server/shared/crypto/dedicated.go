package crypto

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// TenantIsolationResolver reports whether a tenant is on the dedicated/regulated
// isolation tier. enabled=false means the tenant uses shared logical isolation
// under the platform KEK (the default, unchanged behavior).
type TenantIsolationResolver interface {
	DedicatedIsolation(ctx context.Context, tenantID string) (enabled bool, err error)
}

// dedicatedInfo is the HKDF domain-separation label for the dedicated per-tenant
// key domain, distinct from every other key-derivation use in the system.
const dedicatedInfo = "kseal/v1/dedicated-dek"

// Dedicated envelope framing. Material sealed in the dedicated key domain is
// self-describing so OpenForTenant can detect a tier change and fail closed with
// a diagnostic error instead of an opaque AES-GCM failure.
var dedicatedMagic = [4]byte{'K', 'S', 'D', '1'} // kseal dedicated envelope, v1

const dedicatedVersion byte = 1

const dedicatedHeaderLen = 4 + 1 // magic(4) + version(1)

// Dedicated-tier errors mirror the CMK errors: a tier change is surfaced rather
// than swallowed so callers fail closed.
var (
	// ErrDedicatedDisabled indicates a tenant whose dedicated isolation is now
	// off still has dedicated-sealed material. Re-enable the tier to read it, or
	// rotate the tenant's signing key under the platform KEK.
	ErrDedicatedDisabled = errors.New("crypto: dedicated-sealed material but dedicated isolation is disabled for tenant")
	// ErrNotDedicatedEnvelope indicates a dedicated tenant has material that is
	// not a dedicated envelope (sealed before the tier was enabled). Re-seal by
	// rotating the tenant's signing key.
	ErrNotDedicatedEnvelope = errors.New("crypto: expected dedicated envelope")
)

// DedicatedKeyManager is the dedicated/regulated-tier TenantSealer. A tenant on
// the dedicated tier has its secret material sealed under a per-tenant key
// derived (HKDF-SHA256) from the platform KEK with the tenant id as salt, giving
// each such tenant a cryptographically separated key domain: a single derived
// key never opens another tenant's material, and the platform KEK is never used
// directly for dedicated tenants. Tenants not on the tier delegate to the
// fallback sealer (platform KEK or CMK) with byte-identical behavior, so the
// default path and existing sealed material are unchanged.
//
// Dedicated isolation and CMK are mutually exclusive per tenant: the resolver
// reports a tenant dedicated only when it has no customer-managed key, so a CMK
// tenant keeps its customer-controlled DEK domain.
type DedicatedKeyManager struct {
	fallback TenantSealer
	kek      []byte
	resolver TenantIsolationResolver

	mu    sync.RWMutex
	cache map[string]*Encryptor
}

// NewDedicatedKeyManager builds a DedicatedKeyManager. fallback seals
// non-dedicated tenants, kek is the 32-byte platform KEK the per-tenant keys are
// derived from, and resolver decides per tenant which path applies.
func NewDedicatedKeyManager(fallback TenantSealer, kek []byte, resolver TenantIsolationResolver) (*DedicatedKeyManager, error) {
	if fallback == nil {
		return nil, errors.New("crypto: nil fallback sealer")
	}
	if len(kek) != 32 {
		return nil, ErrInvalidKEK
	}
	if resolver == nil {
		return nil, errors.New("crypto: nil tenant isolation resolver")
	}
	kekCopy := make([]byte, len(kek))
	copy(kekCopy, kek)
	return &DedicatedKeyManager{fallback: fallback, kek: kekCopy, resolver: resolver, cache: map[string]*Encryptor{}}, nil
}

// tenantEncryptor returns the cached per-tenant dedicated Encryptor, deriving it
// on first use.
func (m *DedicatedKeyManager) tenantEncryptor(tenantID string) (*Encryptor, error) {
	m.mu.RLock()
	enc, ok := m.cache[tenantID]
	m.mu.RUnlock()
	if ok {
		return enc, nil
	}
	key := make([]byte, dekSize)
	r := hkdf.New(sha256.New, m.kek, []byte(tenantID), []byte(dedicatedInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("crypto: derive dedicated key: %w", err)
	}
	defer zero(key)
	enc, err := NewEncryptor(key)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.cache[tenantID] = enc
	m.mu.Unlock()
	return enc, nil
}

// SealForTenant seals plaintext under the tenant's dedicated per-tenant key when
// the tenant is on the dedicated tier, otherwise under the fallback sealer.
func (m *DedicatedKeyManager) SealForTenant(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error) {
	enabled, err := m.resolver.DedicatedIsolation(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant isolation: %w", err)
	}
	if !enabled {
		return m.fallback.SealForTenant(ctx, tenantID, plaintext)
	}
	enc, err := m.tenantEncryptor(tenantID)
	if err != nil {
		return nil, err
	}
	sealed, err := enc.Seal(plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, dedicatedHeaderLen+len(sealed))
	out = append(out, dedicatedMagic[:]...)
	out = append(out, dedicatedVersion)
	out = append(out, sealed...)
	return out, nil
}

// OpenForTenant reverses SealForTenant. For dedicated tenants it fails closed on
// a tier mismatch rather than reaching for the platform KEK.
func (m *DedicatedKeyManager) OpenForTenant(ctx context.Context, tenantID string, sealed []byte) ([]byte, error) {
	enabled, err := m.resolver.DedicatedIsolation(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant isolation: %w", err)
	}
	if !enabled {
		if hasDedicatedMagic(sealed) {
			return nil, ErrDedicatedDisabled
		}
		return m.fallback.OpenForTenant(ctx, tenantID, sealed)
	}
	if !hasDedicatedMagic(sealed) {
		return nil, ErrNotDedicatedEnvelope
	}
	if sealed[4] != dedicatedVersion {
		return nil, fmt.Errorf("%w: unknown version %d", ErrNotDedicatedEnvelope, sealed[4])
	}
	enc, err := m.tenantEncryptor(tenantID)
	if err != nil {
		return nil, err
	}
	return enc.Open(sealed[dedicatedHeaderLen:])
}

// hasDedicatedMagic reports whether b begins with the dedicated envelope magic.
func hasDedicatedMagic(b []byte) bool {
	return len(b) >= len(dedicatedMagic) && [4]byte(b[:4]) == dedicatedMagic
}
