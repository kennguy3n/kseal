// Command meridian-showcase seeds a running kseal stack with the canonical
// Meridian Pay dataset used throughout the documentation and showcase. It
// provisions one tenant, its apps/builds/policies, the control-plane artifacts
// (API key, webhooks, SIEM connector, data-processing registry, kill switches,
// canary rollout, audit trail) directly through the Postgres-backed stores, and
// then ingests a representative stream of telemetry events over the public
// device-plane HTTP API so every console view renders real, coherent data.
//
// It is a development/operations helper, not part of the product: run it once
// against a freshly started local stack (see deploy/ and the docker-compose
// file) to reproduce the screenshots and worked examples in docs/showcase.
//
// Usage:
//
//	cd examples/meridian-showcase
//	go run . \
//	  -dsn 'postgres://kseal:kseal@localhost:5432/kseal?sslmode=disable' \
//	  -kek ZGV2LW9ubHkta3NlYWwta2VrLTMyLWJ5dGVzLWFhYWE= \
//	  -ingest-url http://localhost:8080
//
// The DSN and KEK must match the running server (the KEK is base64-encoded, the
// same value the server reads from KSEAL_KEK), otherwise sealed signing-key
// material cannot be decrypted to sign kill switches.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"os"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/siem"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	kcrypto "github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
)

func main() {
	dsn := flag.String("dsn", env("KSEAL_POSTGRES_DSN", "postgres://kseal:kseal@localhost:5432/kseal?sslmode=disable"), "Postgres DSN of the running stack")
	kekB64 := flag.String("kek", env("KSEAL_KEK", "ZGV2LW9ubHkta3NlYWwta2VrLTMyLWJ5dGVzLWFhYWE="), "base64-encoded KEK matching the server")
	ingestURL := flag.String("ingest-url", env("KSEAL_INGEST_URL", "http://localhost:8080"), "base URL of the data-plane ingest service")
	eventsOnly := flag.Bool("events-only", false, "re-ingest only the telemetry stream for an already-seeded tenant (use after a server restart clears the in-memory analytics store)")
	flag.Parse()

	if err := run(*dsn, *kekB64, *ingestURL, *eventsOnly); err != nil {
		log.Fatalf("seed failed: %v", err)
	}
}

func run(dsn, kekB64, ingestURL string, eventsOnly bool) error {
	ctx := context.Background()

	kek, err := base64.StdEncoding.DecodeString(kekB64)
	if err != nil {
		return fmt.Errorf("decode KEK: %w", err)
	}

	database, err := db.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect postgres (%s): %w", dsn, err)
	}
	defer database.Close()
	if err := database.Migrate(ctx, migrations.FS); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	enc, err := kcrypto.NewEncryptor(kek)
	if err != nil {
		return fmt.Errorf("build encryptor: %w", err)
	}

	store := registry.NewPostgresStore(database, enc)
	defer store.Close()

	s := &seeder{
		ctx:    ctx,
		store:  store,
		comp:   compliance.NewPostgresStore(database, store),
		siem:   siem.NewPostgresConnectorStore(database, enc),
		ingest: ksealv1connect.NewIngestServiceClient(http.DefaultClient, ingestURL),
		rng:    mrand.New(mrand.NewSource(20240617)),
	}
	if eventsOnly {
		return s.runEventsOnly()
	}
	return s.run()
}

type seeder struct {
	ctx    context.Context
	store  registry.Store
	comp   compliance.Store
	siem   siem.ConnectorStore
	ingest ksealv1connect.IngestServiceClient
	rng    *mrand.Rand
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// hashID returns a deterministic, realistic-looking build hash for a seed string.
func hashID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func randSecret(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
