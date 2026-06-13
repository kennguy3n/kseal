package crypto

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

// fakeKMS is an in-memory stand-in for a cloud KMS. Each keyURI maps to its own
// AES-256-GCM key, so a DEK wrapped under one key cannot be unwrapped under
// another — exactly the isolation property a real KMS provides.
type fakeKMS struct {
	mu        sync.Mutex
	keys      map[string]*Encryptor
	wrapErr   error
	unwrapErr error
}

func newFakeKMS() *fakeKMS { return &fakeKMS{keys: map[string]*Encryptor{}} }

func (f *fakeKMS) encryptor(keyURI string) (*Encryptor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if enc, ok := f.keys[keyURI]; ok {
		return enc, nil
	}
	// Derive a deterministic-but-distinct AES key from the URI for the fake.
	key := make([]byte, 32)
	copy(key, keyURI)
	enc, err := NewEncryptor(key)
	if err != nil {
		return nil, err
	}
	f.keys[keyURI] = enc
	return enc, nil
}

func (f *fakeKMS) Wrap(_ context.Context, keyURI string, plaintextDEK []byte) ([]byte, error) {
	if f.wrapErr != nil {
		return nil, f.wrapErr
	}
	enc, err := f.encryptor(keyURI)
	if err != nil {
		return nil, err
	}
	return enc.Seal(plaintextDEK)
}

func (f *fakeKMS) Unwrap(_ context.Context, keyURI string, wrappedDEK []byte) ([]byte, error) {
	if f.unwrapErr != nil {
		return nil, f.unwrapErr
	}
	enc, err := f.encryptor(keyURI)
	if err != nil {
		return nil, err
	}
	return enc.Open(wrappedDEK)
}

// staticResolver maps tenant IDs to CMK key URIs.
type staticResolver struct {
	uris map[string]string
	err  error
}

func (r staticResolver) KMSKeyURI(_ context.Context, tenantID string) (string, bool, error) {
	if r.err != nil {
		return "", false, r.err
	}
	uri, ok := r.uris[tenantID]
	return uri, ok && uri != "", nil
}

func newPlatformEncryptor(t *testing.T) *Encryptor {
	t.Helper()
	enc, err := NewEncryptor(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestCMKRoundTrip(t *testing.T) {
	ctx := context.Background()
	kms := newFakeKMS()
	resolver := staticResolver{uris: map[string]string{"tenant-a": "kms://customer-a/key-1"}}
	mgr, err := NewCMKKeyManager(newPlatformEncryptor(t), kms, resolver)
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("tenant-a ed25519 private key material")
	sealed, err := mgr.SealForTenant(ctx, "tenant-a", secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if [4]byte(sealed[:4]) != cmkMagic {
		t.Fatal("expected CMK envelope magic for CMK tenant")
	}
	opened, err := mgr.OpenForTenant(ctx, "tenant-a", sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatalf("round-trip mismatch: got %q", opened)
	}
}

func TestCMKPerTenantIsolation(t *testing.T) {
	ctx := context.Background()
	kms := newFakeKMS()
	resolver := staticResolver{uris: map[string]string{
		"tenant-a": "kms://customer-a/key-1",
		"tenant-b": "kms://customer-b/key-1",
	}}
	mgr, err := NewCMKKeyManager(newPlatformEncryptor(t), kms, resolver)
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("only tenant A may read this")
	sealed, err := mgr.SealForTenant(ctx, "tenant-a", secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Opening tenant A's envelope as tenant B must fail: B's key cannot unwrap
	// A's DEK. This proves cryptographic cross-tenant isolation.
	if _, err := mgr.OpenForTenant(ctx, "tenant-b", sealed); err == nil {
		t.Fatal("tenant B unwrapped tenant A's secret")
	}
	// Tenant A still reads its own secret.
	opened, err := mgr.OpenForTenant(ctx, "tenant-a", sealed)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("tenant A self read failed: %v", err)
	}
}

func TestCMKFailClosedOnKMSError(t *testing.T) {
	ctx := context.Background()
	resolver := staticResolver{uris: map[string]string{"tenant-a": "kms://customer-a/key-1"}}
	platform := newPlatformEncryptor(t)

	t.Run("wrap error denies seal", func(t *testing.T) {
		kms := newFakeKMS()
		kms.wrapErr = errors.New("kms unavailable")
		mgr, err := NewCMKKeyManager(platform, kms, resolver)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.SealForTenant(ctx, "tenant-a", []byte("secret")); err == nil {
			t.Fatal("expected seal to fail closed on KMS wrap error")
		}
	})

	t.Run("unwrap error denies open without platform fallback", func(t *testing.T) {
		kms := newFakeKMS()
		mgr, err := NewCMKKeyManager(platform, kms, resolver)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := mgr.SealForTenant(ctx, "tenant-a", []byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		kms.unwrapErr = errors.New("kms denied")
		_, err = mgr.OpenForTenant(ctx, "tenant-a", sealed)
		if err == nil {
			t.Fatal("expected open to fail closed on KMS unwrap error")
		}
		// It must NOT have silently fallen back to the platform KEK.
		if _, fellBack := platform.Open(sealed); fellBack == nil {
			t.Fatal("sealed value should not be platform-openable")
		}
	})
}

func TestCMKPlatformFallbackWhenDisabled(t *testing.T) {
	ctx := context.Background()
	kms := newFakeKMS()
	// tenant-c has no CMK configured -> platform KEK.
	resolver := staticResolver{uris: map[string]string{"tenant-a": "kms://customer-a/key-1"}}
	platform := newPlatformEncryptor(t)
	mgr, err := NewCMKKeyManager(platform, kms, resolver)
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("platform-sealed secret")
	sealed, err := mgr.SealForTenant(ctx, "tenant-c", secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// A non-CMK tenant's blob is plain platform format, not a CMK envelope.
	if len(sealed) >= 4 && [4]byte(sealed[:4]) == cmkMagic {
		t.Fatal("non-CMK tenant should not produce a CMK envelope")
	}
	// And it is directly platform-openable.
	direct, err := platform.Open(sealed)
	if err != nil || !bytes.Equal(direct, secret) {
		t.Fatalf("platform open failed: %v", err)
	}
	// The manager opens it via the same platform fallback path.
	roundtrip, err := mgr.OpenForTenant(ctx, "tenant-c", sealed)
	if err != nil || !bytes.Equal(roundtrip, secret) {
		t.Fatalf("manager platform fallback round-trip failed: %v", err)
	}
}

func TestCMKRejectsPlatformBlobForCMKTenant(t *testing.T) {
	ctx := context.Background()
	platform := newPlatformEncryptor(t)
	// Pre-CMK sealed material, under the platform KEK.
	legacy, err := platform.Seal([]byte("legacy secret"))
	if err != nil {
		t.Fatal(err)
	}
	kms := newFakeKMS()
	resolver := staticResolver{uris: map[string]string{"tenant-a": "kms://customer-a/key-1"}}
	mgr, err := NewCMKKeyManager(platform, kms, resolver)
	if err != nil {
		t.Fatal(err)
	}
	// Now tenant-a is CMK-enabled but the stored blob is a platform blob:
	// must be rejected (not opened with the platform KEK) so the operator
	// re-seals via key rotation.
	_, err = mgr.OpenForTenant(ctx, "tenant-a", legacy)
	if !errors.Is(err, ErrNotCMKEnvelope) {
		t.Fatalf("expected ErrNotCMKEnvelope, got %v", err)
	}
}

func TestCMKResolverErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	mgr, err := NewCMKKeyManager(newPlatformEncryptor(t), newFakeKMS(),
		staticResolver{err: errors.New("db down")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.SealForTenant(ctx, "tenant-a", []byte("x")); err == nil {
		t.Fatal("expected seal to fail when resolver errors")
	}
	if _, err := mgr.OpenForTenant(ctx, "tenant-a", []byte("x")); err == nil {
		t.Fatal("expected open to fail when resolver errors")
	}
}

func TestEncryptorIsTenantSealer(t *testing.T) {
	ctx := context.Background()
	var sealer TenantSealer = newPlatformEncryptor(t)
	secret := []byte("hello")
	sealed, err := sealer.SealForTenant(ctx, "any-tenant", secret)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sealer.OpenForTenant(ctx, "different-tenant", sealed)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("platform sealer ignores tenant id: %v", err)
	}
}

func TestNewCMKKeyManagerValidatesArgs(t *testing.T) {
	platform := newPlatformEncryptor(t)
	kms := newFakeKMS()
	resolver := staticResolver{}
	if _, err := NewCMKKeyManager(nil, kms, resolver); err == nil {
		t.Fatal("expected error for nil platform")
	}
	if _, err := NewCMKKeyManager(platform, nil, resolver); err == nil {
		t.Fatal("expected error for nil kms")
	}
	if _, err := NewCMKKeyManager(platform, kms, nil); err == nil {
		t.Fatal("expected error for nil resolver")
	}
}
