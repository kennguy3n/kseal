package registry

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
)

// TestPostgresStore runs the full store suite against a real Postgres when
// KSEAL_TEST_POSTGRES_DSN is set (e.g. in CI or via testcontainers). It skips
// cleanly otherwise so the default `go test ./...` stays hermetic.
func TestPostgresStore(t *testing.T) {
	dsn := os.Getenv("KSEAL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set KSEAL_TEST_POSTGRES_DSN to run Postgres integration tests")
	}
	ctx := context.Background()
	database, err := db.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(ctx, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	enc, err := crypto.NewEncryptor(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	runStoreSuite(t, NewPostgresStore(database, enc))
}
