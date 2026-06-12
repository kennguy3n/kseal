package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// runStoreSuite exercises the full Store contract. It runs against both the
// in-memory store and (when KSEAL_TEST_POSTGRES_DSN is set) the Postgres store,
// so the two implementations are held to identical semantics.
func runStoreSuite(t *testing.T, store Store) {
	ctx := context.Background()

	t.Run("tenant CRUD", func(t *testing.T) {
		tn, err := store.CreateTenant(ctx, CreateTenantInput{Name: "Acme", Slug: uniqueSlug("acme")})
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.GetTenant(ctx, tn.Id)
		if err != nil || got.Name != "Acme" {
			t.Fatalf("get tenant: %v %+v", err, got)
		}
		upd, err := store.UpdateTenant(ctx, UpdateTenantInput{ID: tn.Id, Tier: "growth"})
		if err != nil || upd.Tier != "growth" {
			t.Fatalf("update tenant: %v %+v", err, upd)
		}
	})

	t.Run("tenant slug unique", func(t *testing.T) {
		slug := uniqueSlug("dup")
		if _, err := store.CreateTenant(ctx, CreateTenantInput{Name: "A", Slug: slug}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreateTenant(ctx, CreateTenantInput{Name: "B", Slug: slug}); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected conflict, got %v", err)
		}
	})

	t.Run("app isolation", func(t *testing.T) {
		a := mustTenant(t, store)
		b := mustTenant(t, store)
		appA, err := store.CreateApp(ctx, CreateAppInput{TenantID: a.Id, Name: "AppA", PackageID: "com.a", Platform: ksealv1.Platform_PLATFORM_ANDROID})
		if err != nil {
			t.Fatal(err)
		}
		// Tenant B cannot read tenant A's app.
		if _, err := store.GetApp(ctx, b.Id, appA.Id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant read leaked: %v", err)
		}
		// Owner can.
		if _, err := store.GetApp(ctx, a.Id, appA.Id); err != nil {
			t.Fatalf("owner read failed: %v", err)
		}
	})

	t.Run("app unique per platform+package", func(t *testing.T) {
		a := mustTenant(t, store)
		in := CreateAppInput{TenantID: a.Id, Name: "X", PackageID: "com.dup", Platform: ksealv1.Platform_PLATFORM_IOS}
		if _, err := store.CreateApp(ctx, in); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreateApp(ctx, in); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected conflict, got %v", err)
		}
	})

	t.Run("policy activation", func(t *testing.T) {
		a := mustTenant(t, store)
		app := mustApp(t, store, a.Id)
		p1, err := store.CreatePolicy(ctx, CreatePolicyInput{TenantID: a.Id, AppID: app.Id, Name: "v1", EnforcementMode: ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE, Rules: "[]", RiskThresholds: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		p2, err := store.CreatePolicy(ctx, CreatePolicyInput{TenantID: a.Id, AppID: app.Id, Name: "v2", EnforcementMode: ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, Rules: "[]", RiskThresholds: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.ActivatePolicy(ctx, a.Id, p1.Id); err != nil {
			t.Fatal(err)
		}
		active, err := store.GetActivePolicy(ctx, a.Id, app.Id)
		if err != nil || active.Id != p1.Id {
			t.Fatalf("active should be p1: %v %+v", err, active)
		}
		// Activating p2 deactivates p1 (single active per scope).
		if _, err := store.ActivatePolicy(ctx, a.Id, p2.Id); err != nil {
			t.Fatal(err)
		}
		active, _ = store.GetActivePolicy(ctx, a.Id, app.Id)
		if active.Id != p2.Id {
			t.Fatalf("active should be p2, got %s", active.Id)
		}
	})

	t.Run("api key validate + revoke", func(t *testing.T) {
		a := mustTenant(t, store)
		plain, rec, err := store.CreateAPIKey(ctx, a.Id, "ci", []string{"admin"})
		if err != nil {
			t.Fatal(err)
		}
		prin, err := store.ValidateAPIKey(ctx, plain)
		if err != nil || prin.TenantID != a.Id {
			t.Fatalf("validate: %v %+v", err, prin)
		}
		if err := store.RevokeAPIKey(ctx, a.Id, rec.KeyID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ValidateAPIKey(ctx, plain); err == nil {
			t.Fatal("revoked key still validates")
		}
	})

	t.Run("signing key rotate", func(t *testing.T) {
		a := mustTenant(t, store)
		k1, err := store.CreateSigningKey(ctx, a.Id)
		if err != nil {
			t.Fatal(err)
		}
		active, err := store.GetActiveSigningKey(ctx, a.Id)
		if err != nil || active.ID != k1.ID {
			t.Fatalf("active key: %v %+v", err, active)
		}
		k2, err := store.RotateSigningKey(ctx, a.Id)
		if err != nil {
			t.Fatal(err)
		}
		active, _ = store.GetActiveSigningKey(ctx, a.Id)
		if active.ID != k2.ID {
			t.Fatalf("rotation did not switch active key")
		}
		if len(active.Private) == 0 || len(active.Public) == 0 {
			t.Fatal("signing key material missing after decrypt")
		}
	})

	t.Run("trust session sequence anti-replay", func(t *testing.T) {
		a := mustTenant(t, store)
		// Token IDs are UUIDs in production (jti from minted trust tokens), which
		// the Postgres schema enforces (trust_sessions.token_id UUID).
		sess := &TrustSession{
			TokenID: uuid.NewString(), TenantID: a.Id, AppID: "app", Status: "active",
			SessionSecret: []byte("s"), IssuedAt: 1, ExpiresAt: 1 << 40,
		}
		if err := store.CreateTrustSession(ctx, sess); err != nil {
			t.Fatal(err)
		}
		if err := store.ConsumeSequence(ctx, sess.TokenID, 1); err != nil {
			t.Fatal(err)
		}
		if err := store.ConsumeSequence(ctx, sess.TokenID, 2); err != nil {
			t.Fatal(err)
		}
		// Replays / non-monotonic sequences are rejected.
		if err := store.ConsumeSequence(ctx, sess.TokenID, 2); !errors.Is(err, ErrReplay) {
			t.Fatalf("expected replay, got %v", err)
		}
		if err := store.ConsumeSequence(ctx, sess.TokenID, 1); !errors.Is(err, ErrReplay) {
			t.Fatalf("expected replay on lower seq, got %v", err)
		}
		// Unknown/inactive sessions are reported as not-found, distinct from replay.
		if err := store.ConsumeSequence(ctx, uuid.NewString(), 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected not-found for unknown token, got %v", err)
		}
	})

	t.Run("webhooks", func(t *testing.T) {
		a := mustTenant(t, store)
		wh, err := store.CreateWebhook(ctx, a.Id, "https://example.com/hook", []ksealv1.EventType{ksealv1.EventType_EVENT_TYPE_ROOT_RISK})
		if err != nil {
			t.Fatal(err)
		}
		list, err := store.ListWebhooks(ctx, a.Id)
		if err != nil || len(list) != 1 {
			t.Fatalf("list webhooks: %v %d", err, len(list))
		}
		secrets, err := store.ListWebhooksForEvent(ctx, a.Id, ksealv1.EventType_EVENT_TYPE_ROOT_RISK)
		if err != nil || len(secrets) != 1 || len(secrets[0].Secret) == 0 {
			t.Fatalf("for-event: %v %+v", err, secrets)
		}
		deleted, err := store.DeleteWebhook(ctx, a.Id, wh.Id)
		if err != nil || !deleted {
			t.Fatalf("delete: %v %v", err, deleted)
		}
	})
}

func TestMemStore(t *testing.T) {
	runStoreSuite(t, NewMemStore())
}

// ---- helpers ----

// runID makes slugs unique across process runs so the suite can run repeatedly
// against a persisted Postgres database without slug collisions.
var runID = uuid.NewString()[:8]

var slugCounter int

func uniqueSlug(prefix string) string {
	slugCounter++
	return prefix + "-" + runID + "-" + itoa(slugCounter)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func mustTenant(t *testing.T, store Store) *ksealv1.Tenant {
	t.Helper()
	tn, err := store.CreateTenant(context.Background(), CreateTenantInput{Name: "T", Slug: uniqueSlug("t")})
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func mustApp(t *testing.T, store Store, tenantID string) *ksealv1.App {
	t.Helper()
	app, err := store.CreateApp(context.Background(), CreateAppInput{TenantID: tenantID, Name: "App", PackageID: uniqueSlug("com.pkg"), Platform: ksealv1.Platform_PLATFORM_ANDROID})
	if err != nil {
		t.Fatal(err)
	}
	return app
}
