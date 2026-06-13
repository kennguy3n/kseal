package registry

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/kseal/server/shared/crypto"
)

func TestRetentionResolverDefaultAndOverride(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	plat, _ := crypto.NewEncryptor(bytes.Repeat([]byte{3}, 32))
	store := NewPostgresStore(database, plat)
	tenant, err := store.CreateTenant(ctx, CreateTenantInput{
		Name: "Ret", Slug: "ret-" + time.Now().Format("150405.000000"),
	})
	if err != nil {
		t.Fatal(err)
	}

	r := NewRetentionResolver(database)

	// Default: no override.
	if _, ok, err := r.RawRetentionDays(ctx, tenant.Id); err != nil || ok {
		t.Fatalf("expected no override by default, ok=%v err=%v", ok, err)
	}

	// Set an override.
	if err := r.SetTenantRawRetentionDays(ctx, tenant.Id, 14); err != nil {
		t.Fatal(err)
	}
	days, ok, err := r.RawRetentionDays(ctx, tenant.Id)
	if err != nil || !ok || days != 14 {
		t.Fatalf("expected 14-day override, got %d ok=%v err=%v", days, ok, err)
	}

	// Clear it (days < 0) -> back to platform default.
	if err := r.SetTenantRawRetentionDays(ctx, tenant.Id, -1); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := r.RawRetentionDays(ctx, tenant.Id); err != nil || ok {
		t.Fatalf("expected override cleared, ok=%v err=%v", ok, err)
	}
}

func TestRetentionResolverUnknownTenant(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	r := NewRetentionResolver(database)
	// A missing tenant reports no override (not an error) so the purger applies
	// the platform default and orphaned events still age out.
	days, ok, err := r.RawRetentionDays(ctx, "00000000-0000-0000-0000-000000000000")
	if err != nil || ok || days != 0 {
		t.Fatalf("expected unknown tenant to report no override, got days=%d ok=%v err=%v", days, ok, err)
	}
}
