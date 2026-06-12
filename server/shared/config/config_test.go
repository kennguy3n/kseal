package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("KSEAL_POSTGRES_DSN", "postgres://localhost/kseal")
	t.Setenv("KSEAL_ENV", "dev")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":8080" {
		t.Fatalf("default http addr = %q", c.HTTPAddr)
	}
	if len(c.KEK) != 32 {
		t.Fatalf("dev KEK len = %d", len(c.KEK))
	}
	if c.NonceTTL == 0 || c.TrustTokenTTL == 0 {
		t.Fatal("ttls should have defaults")
	}
}

func TestLoadRequiresPostgresDSN(t *testing.T) {
	t.Setenv("KSEAL_POSTGRES_DSN", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when DSN missing")
	}
}

func TestLoadProdRequiresKEK(t *testing.T) {
	t.Setenv("KSEAL_POSTGRES_DSN", "postgres://localhost/kseal")
	t.Setenv("KSEAL_ENV", "prod")
	t.Setenv("KSEAL_KEK", "")
	if _, err := Load(); err == nil {
		t.Fatal("prod must require KSEAL_KEK")
	}
}

func TestLoadParsesOverrides(t *testing.T) {
	t.Setenv("KSEAL_POSTGRES_DSN", "postgres://localhost/kseal")
	t.Setenv("KSEAL_NONCE_TTL", "1m")
	t.Setenv("KSEAL_RATE_LIMIT_RPS", "10")
	t.Setenv("KSEAL_CORS_ORIGINS", "https://a.com,https://b.com")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.NonceTTL.String() != "1m0s" {
		t.Fatalf("nonce ttl = %s", c.NonceTTL)
	}
	if c.RateLimitPerSecond != 10 {
		t.Fatalf("rps = %f", c.RateLimitPerSecond)
	}
	if len(c.CORSAllowedOrigins) != 2 {
		t.Fatalf("cors origins = %v", c.CORSAllowedOrigins)
	}
}
