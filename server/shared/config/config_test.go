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

func TestLoadHardeningDefaultsAreOff(t *testing.T) {
	t.Setenv("KSEAL_POSTGRES_DSN", "postgres://localhost/kseal")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.CMKKMSURI != "" {
		t.Fatalf("CMK must default off, got %q", c.CMKKMSURI)
	}
	if c.RedisTLS {
		t.Fatal("Redis TLS must default off")
	}
	if c.RedisPassword != "" {
		t.Fatal("Redis password must default empty")
	}
	if c.OTLPEndpoint != "" {
		t.Fatal("OTLP exporter must default off")
	}
	if c.OTLPSampleRatio != 1.0 {
		t.Fatalf("OTLP sample ratio default = %v", c.OTLPSampleRatio)
	}
	if !c.OTLPInsecure {
		t.Fatal("OTLP insecure should default true")
	}
	if c.RawRetentionDays != 30 {
		t.Fatalf("raw retention default = %d", c.RawRetentionDays)
	}
}

func TestLoadHardeningOverrides(t *testing.T) {
	t.Setenv("KSEAL_POSTGRES_DSN", "postgres://localhost/kseal")
	t.Setenv("KSEAL_CMK_KMS_URI", "https://kms.example.com")
	t.Setenv("KSEAL_REDIS_TLS", "true")
	t.Setenv("KSEAL_REDIS_PASSWORD", "pw")
	t.Setenv("KSEAL_REDIS_CA_FILE", "/etc/ssl/redis-ca.pem")
	t.Setenv("KSEAL_OTLP_ENDPOINT", "otel-collector:4317")
	t.Setenv("KSEAL_OTLP_SAMPLE_RATIO", "0.25")
	t.Setenv("KSEAL_OTLP_INSECURE", "false")
	t.Setenv("KSEAL_RAW_RETENTION_DAYS", "7")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.CMKKMSURI != "https://kms.example.com" {
		t.Fatalf("cmk uri = %q", c.CMKKMSURI)
	}
	if !c.RedisTLS || c.RedisPassword != "pw" || c.RedisCAFile != "/etc/ssl/redis-ca.pem" {
		t.Fatalf("redis hardening not parsed: %+v", c)
	}
	if c.OTLPEndpoint != "otel-collector:4317" || c.OTLPSampleRatio != 0.25 || c.OTLPInsecure {
		t.Fatalf("otlp not parsed: %+v", c)
	}
	if c.RawRetentionDays != 7 {
		t.Fatalf("retention = %d", c.RawRetentionDays)
	}
}

func TestLoadRejectsBadBool(t *testing.T) {
	t.Setenv("KSEAL_POSTGRES_DSN", "postgres://localhost/kseal")
	t.Setenv("KSEAL_REDIS_TLS", "notabool")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid KSEAL_REDIS_TLS")
	}
}
