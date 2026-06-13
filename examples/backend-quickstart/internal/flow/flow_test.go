package flow

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
	"time"
)

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	return k
}

// requireEnv connects to the local Postgres + Redis the example targets. When
// neither is reachable the test skips cleanly so `go test ./...` stays hermetic
// on machines without the docker-compose stack up (mirrors the server harness).
func requireEnv(t *testing.T) *Env {
	t.Helper()
	dsn := envOr("KSEAL_POSTGRES_DSN", "postgres://kseal:kseal@localhost:5432/kseal?sslmode=disable")
	redisAddr := envOr("KSEAL_REDIS_ADDR", "localhost:6379")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env, err := Connect(ctx, dsn, redisAddr)
	if err != nil {
		t.Skipf("backing services unavailable (set KSEAL_POSTGRES_DSN / KSEAL_REDIS_ADDR to run): %v", err)
	}
	t.Cleanup(env.Close)
	return env
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// TestTrustFlowEndToEnd drives the full quickstart against the real services and
// asserts the trust decisions and QueryService reads are what the README claims.
func TestTrustFlowEndToEnd(t *testing.T) {
	env := requireEnv(t)
	ctx := context.Background()

	seed, err := env.Seed(ctx)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	clean, err := env.RunTrustFlow(ctx, seed, Verdict{
		AppRecognition: "PLAY_RECOGNIZED",
		Device:         []string{"MEETS_STRONG_INTEGRITY"},
		Licensing:      "LICENSED",
	})
	if err != nil {
		t.Fatalf("clean trust flow: %v", err)
	}
	if clean.TrustLevel != "TRUSTED" {
		t.Errorf("clean device trust level = %q, want TRUSTED", clean.TrustLevel)
	}
	if clean.Decision != "ALLOW" {
		t.Errorf("clean device proof decision = %q, want ALLOW", clean.Decision)
	}
	if clean.ReplayDecision != "DENY" {
		t.Errorf("replayed proof decision = %q, want DENY (anti-replay)", clean.ReplayDecision)
	}

	risky, err := env.RunTrustFlow(ctx, seed, Verdict{
		AppRecognition: "UNRECOGNIZED_VERSION",
		Device:         []string{},
		Licensing:      "UNLICENSED",
	})
	if err != nil {
		t.Fatalf("risky trust flow: %v", err)
	}
	if risky.Decision != "DENY" {
		t.Errorf("risky device proof decision = %q, want DENY", risky.Decision)
	}

	overview, err := env.TenantOverview(ctx, seed)
	if err != nil {
		t.Fatalf("tenant overview: %v", err)
	}
	if overview.AppCount != 1 || overview.BuildCount != 1 || overview.ActivePolicyCount != 1 {
		t.Errorf("overview = %+v, want apps=1 builds=1 active_policies=1", overview)
	}

	stats, err := env.TrustSessionStats(ctx, seed)
	if err != nil {
		t.Fatalf("trust-session stats: %v", err)
	}
	if stats.Total < 2 {
		t.Errorf("trust sessions total = %d, want >= 2", stats.Total)
	}
	if stats.ByTrustLevel["TRUSTED"] < 1 {
		t.Errorf("expected at least one TRUSTED session, got %v", stats.ByTrustLevel)
	}
}

// TestForgedAttestationRejected proves the verifier rejects a verdict signed by
// a key its (mock) JWKS source does not know — no trust token is minted.
func TestForgedAttestationRejected(t *testing.T) {
	env := requireEnv(t)
	ctx := context.Background()

	seed, err := env.Seed(ctx)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Point the signing key at a fresh, unknown RSA key so the JWS signature
	// fails verification against the mock JWKS.
	forged := *env
	forged.playPriv = mustRSAKey(t)

	_, err = forged.RunTrustFlow(ctx, seed, Verdict{
		AppRecognition: "PLAY_RECOGNIZED",
		Device:         []string{"MEETS_STRONG_INTEGRITY"},
		Licensing:      "LICENSED",
	})
	if err == nil {
		t.Fatal("expected attestation rejection for forged JWS signature, got nil error")
	}
}
