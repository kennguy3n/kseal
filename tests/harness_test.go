// Package tests holds the real end-to-end integration suite for kseal. Every
// test here drives the actual server services (control-plane registry +
// data-plane trust/ingest/query/config/webhook) against a real Postgres 16 and
// Redis 7. The only things mocked are the external third-party attestation
// platforms (Google Play Integrity / Apple App Attest) — and even there only
// their external trust-material source is replaced, so the real JWS parsing and
// verdict mapping run.
//
// Backing services are provisioned once per package run in TestMain. They come
// from KSEAL_TEST_POSTGRES_DSN / KSEAL_TEST_REDIS_ADDR when set, otherwise from
// testcontainers (Postgres 16 + Redis 7). When neither a DSN nor a container
// runtime is available the whole suite skips cleanly so `go test ./...` stays
// hermetic on machines without Docker.
package tests

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
)

// Shared, package-level backing services established by TestMain. When
// harnessErr is non-nil the harness could not be provisioned and every test
// skips via requireHarness.
var (
	sharedDB        *db.DB
	sharedRedisAddr string
	harnessErr      error
)

// testKEK is a deterministic 32-byte key-encryption key for the registry
// encryptor. It only protects signing-key material inside the ephemeral test
// database, so a fixed value is fine (mirrors server/.../postgres_test.go).
var testKEK = bytes.Repeat([]byte{7}, 32)

func TestMain(m *testing.M) {
	code := runMain(m)
	os.Exit(code)
}

// runMain provisions the harness, runs the suite, and tears down — split out so
// deferred cleanup runs before os.Exit.
func runMain(m *testing.M) int {
	cleanup, err := setupHarness()
	if err != nil {
		// Record the failure; individual tests skip rather than fail so the
		// suite is hermetic without Docker. m.Run still runs to register skips.
		harnessErr = err
	}
	if cleanup != nil {
		defer cleanup()
	}
	return m.Run()
}

// setupHarness wires Postgres + Redis, preferring explicit env endpoints and
// falling back to testcontainers. It runs migrations once. The returned cleanup
// terminates any containers it started.
func setupHarness() (func(), error) {
	ctx := context.Background()
	dsn := os.Getenv("KSEAL_TEST_POSTGRES_DSN")
	redisAddr := os.Getenv("KSEAL_TEST_REDIS_ADDR")

	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	if dsn == "" {
		pgDSN, pgClean, err := startPostgres(ctx)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("start postgres: %w", err)
		}
		cleanups = append(cleanups, pgClean)
		dsn = pgDSN
	}
	if redisAddr == "" {
		addr, redisClean, err := startRedis(ctx)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("start redis: %w", err)
		}
		cleanups = append(cleanups, redisClean)
		redisAddr = addr
	}

	database, err := db.New(ctx, dsn)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	cleanups = append(cleanups, database.Close)
	if err := database.Migrate(ctx, migrations.FS); err != nil {
		cleanup()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	// Verify Redis connectivity up front so a broken endpoint surfaces as a
	// clean skip rather than mid-test failures.
	rc := redis.NewClient(&redis.Options{Addr: redisAddr})
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rc.Ping(pingCtx).Err(); err != nil {
		_ = rc.Close()
		cleanup()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	_ = rc.Close()

	sharedDB = database
	sharedRedisAddr = redisAddr
	return cleanup, nil
}

func startPostgres(ctx context.Context) (string, func(), error) {
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("kseal"),
		tcpostgres.WithUsername("kseal"),
		tcpostgres.WithPassword("kseal"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("5432/tcp").WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		return "", nil, err
	}
	clean := func() { _ = c.Terminate(context.Background()) }
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		clean()
		return "", nil, err
	}
	return dsn, clean, nil
}

func startRedis(ctx context.Context) (string, func(), error) {
	c, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		return "", nil, err
	}
	clean := func() { _ = c.Terminate(context.Background()) }
	endpoint, err := c.Endpoint(ctx, "")
	if err != nil {
		clean()
		return "", nil, err
	}
	return endpoint, clean, nil
}

// requireHarness skips the calling test when the backing services could not be
// provisioned (no env endpoints and no container runtime).
func requireHarness(t *testing.T) {
	t.Helper()
	if harnessErr != nil {
		t.Skipf("integration harness unavailable (set KSEAL_TEST_POSTGRES_DSN/KSEAL_TEST_REDIS_ADDR or provide a container runtime): %v", harnessErr)
	}
}

// newStore builds a Postgres-backed registry store over the shared database.
func newStore(t *testing.T) registry.Store {
	t.Helper()
	enc, err := crypto.NewEncryptor(testKEK)
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	return registry.NewPostgresStore(sharedDB, enc)
}

// newRedis returns a client to the shared Redis, closed on test cleanup.
func newRedis(t *testing.T) *redis.Client {
	t.Helper()
	rc := redis.NewClient(&redis.Options{Addr: sharedRedisAddr})
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

// uniqueSlug yields a tenant slug unique to this test so concurrently-developed
// tests never collide in the shared database.
func uniqueSlug(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// makeTenant creates a tenant with a unique slug.
func makeTenant(t *testing.T, store registry.Store, prefix string) *ksealv1.Tenant {
	t.Helper()
	tn, err := store.CreateTenant(context.Background(), registry.CreateTenantInput{
		Name: prefix, Slug: uniqueSlug(prefix), Tier: "growth",
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn
}

// makeApp registers an Android app under the tenant.
func makeApp(t *testing.T, store registry.Store, tenantID, pkg string) *ksealv1.App {
	t.Helper()
	app, err := store.CreateApp(context.Background(), registry.CreateAppInput{
		TenantID: tenantID, Name: pkg, PackageID: pkg, Platform: ksealv1.Platform_PLATFORM_ANDROID,
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	return app
}

// buildHash is a deterministic registered build hash used across tests.
const buildHash = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// makeBuild registers an immutable build for the app.
func makeBuild(t *testing.T, store registry.Store, tenantID, appID string) *ksealv1.Build {
	t.Helper()
	b, err := store.CreateBuild(context.Background(), registry.CreateBuildInput{
		TenantID: tenantID, AppID: appID, BuildHash: buildHash,
		VersionName: "1.0.0", VersionCode: 1, Manifest: "{}",
	})
	if err != nil {
		t.Fatalf("create build: %v", err)
	}
	return b
}

// activatePolicy creates and activates a policy version for the app.
func activatePolicy(t *testing.T, store registry.Store, tenantID, appID string, mode ksealv1.EnforcementMode, rules, thresholds string) *ksealv1.Policy {
	t.Helper()
	ctx := context.Background()
	p, err := store.CreatePolicy(ctx, registry.CreatePolicyInput{
		TenantID: tenantID, AppID: appID, Name: "v1",
		EnforcementMode: mode, Rules: rules, RiskThresholds: thresholds,
		ModulesEnabled: []string{"root", "debugger"},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	active, err := store.ActivatePolicy(ctx, tenantID, p.Id)
	if err != nil {
		t.Fatalf("activate policy: %v", err)
	}
	return active
}
