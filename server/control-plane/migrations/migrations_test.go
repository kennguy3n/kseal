package migrations_test

import (
	"strings"
	"testing"

	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/shared/db"
)

func TestMigrationsLoadInOrder(t *testing.T) {
	ms, err := db.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) < 8 {
		t.Fatalf("expected at least 8 migrations, got %d", len(ms))
	}
	// Lexical order must be ascending so numbered files apply 001..00N.
	for i := 1; i < len(ms); i++ {
		if ms[i-1].Name >= ms[i].Name {
			t.Fatalf("migrations out of order: %s before %s", ms[i-1].Name, ms[i].Name)
		}
	}
	// Every tenant-scoped table must enable row-level security.
	all := ""
	for _, m := range ms {
		all += m.SQL + "\n"
	}
	for _, tbl := range []string{"apps", "builds", "api_keys", "policies", "protection_profiles", "signing_keys", "webhooks", "trust_sessions"} {
		if !strings.Contains(all, "ALTER TABLE "+tbl+" ENABLE ROW LEVEL SECURITY") {
			t.Fatalf("expected RLS to be enabled on table %s", tbl)
		}
	}
}
