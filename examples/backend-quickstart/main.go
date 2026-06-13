// Command backend-quickstart is a runnable, end-to-end walkthrough of the kseal
// device trust flow against the real server services. It exercises the public
// API surface exactly as a backend integrator would reason about it:
//
//	GetNonce -> VerifyAttestation -> ValidateRequestProof (ALLOW/STEP_UP/DENY)
//	          -> QueryService read (tenant overview + trust-session stats)
//
// The services are the real ones (registry, trust, query) running against a
// real Postgres 16 + Redis 7. The ONLY thing mocked is the external attestation
// provider (Google Play Integrity): its JWKS source is swapped for a locally
// generated RSA key so the real JWS parsing, nonce binding, and verdict->risk
// mapping still run. This mirrors the documented test path in
// tests/e2e_trust_flow_test.go and the "mock only external services" rule.
//
// Usage:
//
//	# bring up Postgres + Redis (e.g. `make docker-up`, or standalone), then:
//	export KSEAL_POSTGRES_DSN="postgres://kseal:kseal@localhost:5432/kseal?sslmode=disable"
//	export KSEAL_REDIS_ADDR="localhost:6379"
//	go run .
//
// Both env vars default to the local docker-compose endpoints, so on a fresh
// `make docker-up` you can just `go run .`.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kennguy3n/kseal/examples/backend-quickstart/internal/flow"
)

func main() {
	seedOnly := flag.Bool("seed", false, "only provision a tenant/app/build/policy + API key against the (live) database and print shell exports for curl-quickstart.sh, then exit")
	flag.Parse()
	if err := run(*seedOnly); err != nil {
		fmt.Fprintln(os.Stderr, "backend-quickstart failed:", err)
		os.Exit(1)
	}
}

func run(seedOnly bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dsn := envOr("KSEAL_POSTGRES_DSN", "postgres://kseal:kseal@localhost:5432/kseal?sslmode=disable")
	redisAddr := envOr("KSEAL_REDIS_ADDR", "localhost:6379")

	env, err := flow.Connect(ctx, dsn, redisAddr)
	if err != nil {
		return err
	}
	defer env.Close()

	if seedOnly {
		seed, err := env.Seed(ctx)
		if err != nil {
			return err
		}
		// Emit shell exports so `eval "$(go run . -seed)"` wires curl-quickstart.sh.
		// Single-quote the values so any shell metacharacter is treated literally
		// (these ids never contain a single quote, so no escaping is needed).
		fmt.Printf("export KSEAL_API_KEY='%s'\n", seed.APIKey)
		fmt.Printf("export KSEAL_TENANT='%s'\n", seed.TenantID)
		fmt.Printf("export KSEAL_APP='%s'\n", seed.AppID)
		return nil
	}

	step(1, "Seed a tenant, app, build, active policy, and a control-plane API key")
	seed, err := env.Seed(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("    tenant_id = %s\n    app_id    = %s (%s)\n    build     = %s\n", seed.TenantID, seed.AppID, seed.PackageID, flow.BuildHash)
	fmt.Printf("    api_key   = %s   (control-plane: send as `Authorization: Bearer <key>`)\n", seed.APIKey)

	step(2, "Device plane: GetNonce -> VerifyAttestation -> ValidateRequestProof")
	allow, err := env.RunTrustFlow(ctx, seed, flow.Verdict{
		AppRecognition: "PLAY_RECOGNIZED",
		Device:         []string{"MEETS_STRONG_INTEGRITY"},
		Licensing:      "LICENSED",
	})
	if err != nil {
		return err
	}
	fmt.Printf("    clean device -> trust level %s, token %s\n", allow.TrustLevel, short(allow.TokenID))
	fmt.Printf("    request proof (seq=1) decision: %s\n", allow.Decision)
	fmt.Printf("    replayed proof (seq=1) decision: %s  (anti-replay)\n", allow.ReplayDecision)

	step(3, "A risky device steps up / is denied by the SAME policy (server-authoritative)")
	risky, err := env.RunTrustFlow(ctx, seed, flow.Verdict{
		AppRecognition: "UNRECOGNIZED_VERSION",
		Device:         []string{},
		Licensing:      "UNLICENSED",
	})
	if err != nil {
		return err
	}
	fmt.Printf("    tampered/unrecognized device -> trust level %s, decision %s\n", risky.TrustLevel, risky.Decision)

	step(4, "QueryService read: tenant overview + trust-session stats")
	overview, err := env.TenantOverview(ctx, seed)
	if err != nil {
		return err
	}
	fmt.Printf("    apps=%d builds=%d active_policies=%d\n", overview.AppCount, overview.BuildCount, overview.ActivePolicyCount)
	stats, err := env.TrustSessionStats(ctx, seed)
	if err != nil {
		return err
	}
	fmt.Printf("    trust sessions: total=%d tokens_issued=%d attestations_failed=%d by_level=%v\n",
		stats.Total, stats.TokensIssued, stats.AttestationsFailed, stats.ByTrustLevel)

	fmt.Println("\nDone. See README.md for the equivalent curl walkthrough against a live `make docker-up` server.")
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func step(n int, title string) { fmt.Printf("\n[%d] %s\n", n, title) }

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "…"
}
