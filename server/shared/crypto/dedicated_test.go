package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// fakeIsolation is a test resolver: tenants in the set are on the dedicated tier.
type fakeIsolation struct {
	dedicated map[string]bool
	err       error
}

func (f fakeIsolation) DedicatedIsolation(_ context.Context, tenantID string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.dedicated[tenantID], nil
}

func newManager(t *testing.T, iso fakeIsolation) (*DedicatedKeyManager, *Encryptor) {
	t.Helper()
	kek := bytes.Repeat([]byte{7}, 32)
	platform, err := NewEncryptor(kek)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewDedicatedKeyManager(platform, kek, iso)
	if err != nil {
		t.Fatal(err)
	}
	return mgr, platform
}

func TestDedicatedRoundTrip(t *testing.T) {
	ctx := context.Background()
	mgr, _ := newManager(t, fakeIsolation{dedicated: map[string]bool{"ded": true}})
	pt := []byte("super-secret-signing-key-material")

	sealed, err := mgr.SealForTenant(ctx, "ded", pt)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDedicatedMagic(sealed) {
		t.Fatal("dedicated tenant material must carry the dedicated envelope magic")
	}
	got, err := mgr.OpenForTenant(ctx, "ded", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("round trip mismatch")
	}
}

func TestDedicatedKeySeparation(t *testing.T) {
	ctx := context.Background()
	mgr, _ := newManager(t, fakeIsolation{dedicated: map[string]bool{"a": true, "b": true}})
	sealed, err := mgr.SealForTenant(ctx, "a", []byte("a-secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Tenant b must not be able to open tenant a's material: distinct derived keys.
	if _, err := mgr.OpenForTenant(ctx, "b", sealed); err == nil {
		t.Fatal("tenant b must not open tenant a's dedicated material")
	}
}

func TestDedicatedFallbackForNonDedicated(t *testing.T) {
	ctx := context.Background()
	mgr, platform := newManager(t, fakeIsolation{dedicated: map[string]bool{"ded": true}})
	pt := []byte("shared-tier-secret")

	sealed, err := mgr.SealForTenant(ctx, "shared", pt)
	if err != nil {
		t.Fatal(err)
	}
	if hasDedicatedMagic(sealed) {
		t.Fatal("non-dedicated tenant must not get a dedicated envelope")
	}
	// Byte-identical to the platform sealer path: the manager is transparent.
	if _, err := platform.OpenForTenant(ctx, "shared", sealed); err != nil {
		t.Fatalf("platform sealer must open non-dedicated material: %v", err)
	}
	got, err := mgr.OpenForTenant(ctx, "shared", sealed)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("non-dedicated round trip failed: %v", err)
	}
}

func TestDedicatedTierMismatchFailsClosed(t *testing.T) {
	ctx := context.Background()

	// Material sealed while dedicated, tenant later downgraded -> fail closed.
	on := fakeIsolation{dedicated: map[string]bool{"t": true}}
	mgrOn, _ := newManager(t, on)
	sealed, err := mgrOn.SealForTenant(ctx, "t", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	mgrOff, _ := newManager(t, fakeIsolation{dedicated: map[string]bool{}})
	if _, err := mgrOff.OpenForTenant(ctx, "t", sealed); !errors.Is(err, ErrDedicatedDisabled) {
		t.Fatalf("expected ErrDedicatedDisabled, got %v", err)
	}

	// Material sealed while shared, tenant later upgraded -> expect dedicated env.
	mgrOff2, platform := newManager(t, fakeIsolation{dedicated: map[string]bool{}})
	shared, err := mgrOff2.SealForTenant(ctx, "t", []byte("y"))
	if err != nil {
		t.Fatal(err)
	}
	_ = platform
	mgrOn2, _ := newManager(t, fakeIsolation{dedicated: map[string]bool{"t": true}})
	if _, err := mgrOn2.OpenForTenant(ctx, "t", shared); !errors.Is(err, ErrNotDedicatedEnvelope) {
		t.Fatalf("expected ErrNotDedicatedEnvelope, got %v", err)
	}
}

func TestDedicatedResolverErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	mgr, _ := newManager(t, fakeIsolation{err: errors.New("db down")})
	if _, err := mgr.SealForTenant(ctx, "t", []byte("x")); err == nil {
		t.Fatal("seal must fail closed when isolation lookup errors")
	}
	if _, err := mgr.OpenForTenant(ctx, "t", []byte("x")); err == nil {
		t.Fatal("open must fail closed when isolation lookup errors")
	}
}

func TestDedicatedConstructorValidation(t *testing.T) {
	platform, _ := NewEncryptor(bytes.Repeat([]byte{1}, 32))
	iso := fakeIsolation{}
	if _, err := NewDedicatedKeyManager(nil, bytes.Repeat([]byte{1}, 32), iso); err == nil {
		t.Fatal("nil fallback must error")
	}
	if _, err := NewDedicatedKeyManager(platform, []byte{1, 2, 3}, iso); err == nil {
		t.Fatal("short KEK must error")
	}
	if _, err := NewDedicatedKeyManager(platform, bytes.Repeat([]byte{1}, 32), nil); err == nil {
		t.Fatal("nil resolver must error")
	}
}
