package compliance

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
)

// pgStore spins up the Postgres-backed compliance store against a real database
// when KSEAL_TEST_POSTGRES_DSN is set, returning the store, the registry store
// (KeySource), and the database handle. It skips cleanly otherwise.
func pgStore(t *testing.T) (*PostgresStore, *registry.PostgresStore, *db.DB) {
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
	enc, err := crypto.NewEncryptor(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.NewPostgresStore(database, enc)
	return NewPostgresStore(database, reg), reg, database
}

func mkTenant(t *testing.T, reg *registry.PostgresStore, slug string) string {
	t.Helper()
	// Unique slug per run so the suite is re-runnable against a persistent DB.
	uniq := slug + "-" + uuid.NewString()[:8]
	tn, err := reg.CreateTenant(context.Background(), registry.CreateTenantInput{Name: slug, Slug: uniq})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn.Id
}

func TestPGAuditChainAndIsolation(t *testing.T) {
	s, reg, _ := pgStore(t)
	ctx := context.Background()
	ta := mkTenant(t, reg, "pg-audit-a")
	tb := mkTenant(t, reg, "pg-audit-b")

	for i := 0; i < 3; i++ {
		if _, err := s.AppendAudit(ctx, ta, Entry{Action: "policy.update"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AppendAudit(ctx, tb, Entry{Action: "key.rotate"}); err != nil {
		t.Fatal(err)
	}

	res, err := s.VerifyAudit(ctx, ta)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact || res.VerifiedCount != 3 {
		t.Fatalf("expected 3 intact events, got %+v", res)
	}

	// RLS isolation: tenant b's listing never includes tenant a's events.
	evb, _, err := s.ListAudit(ctx, tb, AuditFilter{}, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(evb) != 1 || evb[0].Action != "key.rotate" {
		t.Fatalf("tenant b isolation broken: %+v", evb)
	}
}

func TestPGAuditAppendOnlyTrigger(t *testing.T) {
	s, reg, database := pgStore(t)
	ctx := context.Background()
	tn := mkTenant(t, reg, "pg-append-only")
	if _, err := s.AppendAudit(ctx, tn, Entry{Action: "policy.update"}); err != nil {
		t.Fatal(err)
	}

	// Within the tenant context (not the admin bypass), UPDATE/DELETE must be
	// rejected by the append-only trigger.
	err := database.WithTenantTx(ctx, tn, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE audit_events SET action = 'tampered' WHERE tenant_id = $1`, tn)
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("expected append-only rejection, got %v", err)
	}

	err = database.WithTenantTx(ctx, tn, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1`, tn)
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("expected append-only rejection on delete, got %v", err)
	}
}

func TestPGKillSwitchSignAndVersion(t *testing.T) {
	s, reg, _ := pgStore(t)
	ctx := context.Background()
	tn := mkTenant(t, reg, "pg-killswitch")

	ks, err := s.IssueKillSwitch(ctx, KillSwitchInput{
		TenantID: tn, AppID: "app1", Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
	})
	if err != nil {
		t.Fatal(err)
	}
	sk, err := reg.GetActiveSigningKey(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyKillSwitch(sk.Public, ks) {
		t.Fatal("kill switch must verify against tenant key")
	}
	ks2, err := s.IssueKillSwitch(ctx, KillSwitchInput{
		TenantID: tn, AppID: "app1", Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ks2.Version != ks.Version+1 {
		t.Fatalf("re-issue must bump version: %d -> %d", ks.Version, ks2.Version)
	}
}

func TestPGCanaryLifecycleAndActiveSweep(t *testing.T) {
	s, reg, _ := pgStore(t)
	ctx := context.Background()
	tn := mkTenant(t, reg, "pg-canary")

	if _, err := s.SetCanary(ctx, CanaryInput{
		TenantID: tn, AppID: "app1", CandidatePolicyID: "cand", StablePolicyID: "stable", Percent: 25,
	}); err != nil {
		t.Fatal(err)
	}

	// Cross-tenant admin sweep sees the active canary.
	active, err := s.ListActiveCanaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cs := range active {
		if cs.TenantId == tn && cs.AppId == "app1" {
			found = true
		}
	}
	if !found {
		t.Fatal("active sweep must include the new canary")
	}

	rb, err := s.RollbackCanary(ctx, tn, "app1", "guardrail breach", "actor", CanaryObservation{BlockRate: 0.3, SampleCount: 80})
	if err != nil {
		t.Fatal(err)
	}
	if rb.State != ksealv1.CanaryState_CANARY_STATE_ROLLED_BACK || rb.Percent != 0 {
		t.Fatalf("rollback should zero and mark rolled back: %+v", rb)
	}
}

func TestPGDedicatedResolver(t *testing.T) {
	_, reg, database := pgStore(t)
	ctx := context.Background()
	tn := mkTenant(t, reg, "pg-dedicated")
	res := registry.NewDedicatedResolver(database, 0)

	enabled, err := res.DedicatedIsolation(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("tenant must default to shared isolation")
	}
	if err := res.SetTenantDedicatedIsolation(ctx, tn, true); err != nil {
		t.Fatal(err)
	}
	enabled, err = res.DedicatedIsolation(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("tenant must report dedicated after enabling")
	}
}
