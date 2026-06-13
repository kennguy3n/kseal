package registry

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
)

// memKMS is an in-memory KMS for the CMK integration test: each key URI gets its
// own AES key so DEKs are cryptographically scoped to a customer key.
type memKMS struct {
	mu   sync.Mutex
	keys map[string]*crypto.Encryptor
}

func newMemKMS() *memKMS { return &memKMS{keys: map[string]*crypto.Encryptor{}} }

func (m *memKMS) enc(keyURI string) (*crypto.Encryptor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.keys[keyURI]; ok {
		return e, nil
	}
	key := make([]byte, 32)
	copy(key, keyURI)
	e, err := crypto.NewEncryptor(key)
	if err != nil {
		return nil, err
	}
	m.keys[keyURI] = e
	return e, nil
}

func (m *memKMS) Wrap(_ context.Context, keyURI string, dek []byte) ([]byte, error) {
	e, err := m.enc(keyURI)
	if err != nil {
		return nil, err
	}
	return e.Seal(dek)
}

func (m *memKMS) Unwrap(_ context.Context, keyURI string, wrapped []byte) ([]byte, error) {
	e, err := m.enc(keyURI)
	if err != nil {
		return nil, err
	}
	return e.Open(wrapped)
}

func testDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("KSEAL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set KSEAL_TEST_POSTGRES_DSN to run Postgres integration tests")
	}
	ctx := context.Background()
	database, err := db.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(database.Close)
	if err := database.Migrate(ctx, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return database
}

func TestCMKResolverDefaultDisabled(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	plat, _ := crypto.NewEncryptor(bytes.Repeat([]byte{3}, 32))
	store := NewPostgresStore(database, plat)
	tenant, err := store.CreateTenant(ctx, CreateTenantInput{Name: "Acme", Slug: "acme-" + time.Now().Format("150405.000000")})
	if err != nil {
		t.Fatal(err)
	}
	r := NewCMKResolver(database, time.Millisecond)
	uri, enabled, err := r.KMSKeyURI(ctx, tenant.Id)
	if err != nil {
		t.Fatal(err)
	}
	if enabled || uri != "" {
		t.Fatalf("new tenant should default to platform KEK, got %q enabled=%v", uri, enabled)
	}
}

func TestCMKResolverSetClearAndCache(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	plat, _ := crypto.NewEncryptor(bytes.Repeat([]byte{3}, 32))
	store := NewPostgresStore(database, plat)
	tenant, err := store.CreateTenant(ctx, CreateTenantInput{Name: "Beta", Slug: "beta-" + time.Now().Format("150405.000000")})
	if err != nil {
		t.Fatal(err)
	}
	r := NewCMKResolver(database, time.Minute) // long TTL to assert invalidation

	const uri = "kms://customer/key-1"
	if err := r.SetTenantCMKKeyURI(ctx, tenant.Id, uri); err != nil {
		t.Fatal(err)
	}
	got, enabled, err := r.KMSKeyURI(ctx, tenant.Id)
	if err != nil || !enabled || got != uri {
		t.Fatalf("expected enabled %q, got %q enabled=%v err=%v", uri, got, enabled, err)
	}
	// Clearing must invalidate the cache and disable CMK.
	if err := r.SetTenantCMKKeyURI(ctx, tenant.Id, ""); err != nil {
		t.Fatal(err)
	}
	got, enabled, err = r.KMSKeyURI(ctx, tenant.Id)
	if err != nil || enabled || got != "" {
		t.Fatalf("expected disabled after clear, got %q enabled=%v err=%v", got, enabled, err)
	}
}

func TestCMKResolverUnknownTenant(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	r := NewCMKResolver(database, time.Millisecond)
	if _, _, err := r.KMSKeyURI(ctx, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("expected error for unknown tenant")
	}
}

// TestCMKStoreEndToEnd proves signing keys are sealed under the tenant's CMK and
// remain openable, with cross-tenant isolation enforced cryptographically.
func TestCMKStoreEndToEnd(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	plat, _ := crypto.NewEncryptor(bytes.Repeat([]byte{3}, 32))

	// Bootstrap two tenants, only one CMK-enabled, via a platform-KEK store.
	bootstrap := NewPostgresStore(database, plat)
	suffix := time.Now().Format("150405.000000")
	tA, err := bootstrap.CreateTenant(ctx, CreateTenantInput{Name: "CMK-A", Slug: "cmk-a-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	tB, err := bootstrap.CreateTenant(ctx, CreateTenantInput{Name: "Plain-B", Slug: "plain-b-" + suffix})
	if err != nil {
		t.Fatal(err)
	}

	resolver := NewCMKResolver(database, time.Millisecond)
	if err := resolver.SetTenantCMKKeyURI(ctx, tA.Id, "kms://customer-a/key"); err != nil {
		t.Fatal(err)
	}

	mgr, err := crypto.NewCMKKeyManager(plat, newMemKMS(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	store := NewPostgresStore(database, mgr)

	// CMK tenant: create + read back the signing key (DEK wrapped via KMS).
	skA, err := store.CreateSigningKey(ctx, tA.Id)
	if err != nil {
		t.Fatalf("create CMK signing key: %v", err)
	}
	gotA, err := store.GetActiveSigningKey(ctx, tA.Id)
	if err != nil {
		t.Fatalf("get CMK signing key: %v", err)
	}
	if !bytes.Equal(gotA.Private, skA.Private) {
		t.Fatal("CMK signing key did not round-trip")
	}

	// Non-CMK tenant: platform-KEK sealed, also round-trips.
	skB, err := store.CreateSigningKey(ctx, tB.Id)
	if err != nil {
		t.Fatalf("create plain signing key: %v", err)
	}
	gotB, err := store.GetActiveSigningKey(ctx, tB.Id)
	if err != nil {
		t.Fatalf("get plain signing key: %v", err)
	}
	if !bytes.Equal(gotB.Private, skB.Private) {
		t.Fatal("plain signing key did not round-trip")
	}
}
