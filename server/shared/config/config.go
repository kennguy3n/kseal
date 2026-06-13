// Package config loads and validates the kseal server configuration from the
// environment. Only the canonical KSEAL_* variables are recognized; secrets are
// never read from files (KMS-backed secret loading is future work).
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-validated server configuration.
type Config struct {
	HTTPAddr    string
	PostgresDSN string
	RedisAddr   string
	RedisDB     int
	LogLevel    string
	Env         string

	// KEK is the 32-byte key-encryption key used to protect signing-key private
	// material at rest. Supplied base64-encoded via KSEAL_KEK. In non-prod
	// environments a deterministic development key is derived when unset.
	KEK []byte

	// NonceTTL is how long an attestation challenge nonce remains valid.
	NonceTTL time.Duration
	// TrustTokenTTL is the default lifetime of a minted trust token.
	TrustTokenTTL time.Duration
	// ConfigTTL is the client-side cache lifetime advertised for signed configs.
	ConfigTTL time.Duration

	// RateLimitPerSecond is the per-tenant token-bucket refill rate.
	RateLimitPerSecond float64
	// RateLimitBurst is the per-tenant token-bucket capacity.
	RateLimitBurst int

	// IngestQuotaPerMinute is the default per-tenant event quota.
	IngestQuotaPerMinute int

	// CORSAllowedOrigins lists origins permitted to call the API from a browser.
	CORSAllowedOrigins []string

	// FeatureFlags holds per-tenant feature toggles parsed from
	// KSEAL_FEATURE_FLAGS (format: tenant:flag=bool,...).
	FeatureFlags FeatureFlags

	// CMKKMSURI is the customer-managed-key (BYOK/CMK) KMS endpoint base URL.
	// Empty disables CMK entirely: every tenant uses the platform KEK
	// (unchanged behavior). When set, tenants whose cmk_kms_uri column is
	// populated have their DEKs wrapped by their own KMS key; the rest still
	// fall back to the platform KEK.
	CMKKMSURI string
	// CMKKMSAuthToken is an optional bearer token presented to the KMS endpoint.
	CMKKMSAuthToken string

	// RedisTLS enables TLS to Redis (default false, plaintext).
	RedisTLS bool
	// RedisCAFile optionally pins the Redis server CA (PEM). Empty uses system
	// roots.
	RedisCAFile string
	// RedisPassword is the Redis AUTH credential (default empty, no AUTH).
	RedisPassword string

	// OTLPEndpoint is the OTLP/gRPC trace collector address (host:port). Empty
	// attaches no exporter (current behavior).
	OTLPEndpoint string
	// OTLPSampleRatio is the head-sampling ratio in [0,1] (default 1.0).
	OTLPSampleRatio float64
	// OTLPInsecure disables transport security to the collector (default true).
	OTLPInsecure bool

	// RawRetentionDays is the platform-default raw-telemetry retention window in
	// days, applied to tenants without a per-tenant override. <= 0 retains raw
	// events indefinitely (fail-safe).
	RawRetentionDays int
}

// IsProd reports whether the server runs in a production-like environment.
func (c *Config) IsProd() bool {
	switch strings.ToLower(c.Env) {
	case "prod", "production", "staging":
		return true
	default:
		return false
	}
}

// Load reads configuration from the process environment and validates it.
func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:             getenv("KSEAL_HTTP_ADDR", ":8080"),
		PostgresDSN:          os.Getenv("KSEAL_POSTGRES_DSN"),
		RedisAddr:            getenv("KSEAL_REDIS_ADDR", "localhost:6379"),
		LogLevel:             getenv("KSEAL_LOG_LEVEL", "info"),
		Env:                  getenv("KSEAL_ENV", "dev"),
		NonceTTL:             5 * time.Minute,
		TrustTokenTTL:        15 * time.Minute,
		ConfigTTL:            5 * time.Minute,
		RateLimitPerSecond:   100,
		RateLimitBurst:       200,
		IngestQuotaPerMinute: 60000,
		CORSAllowedOrigins:   splitNonEmpty(getenv("KSEAL_CORS_ORIGINS", "http://localhost:5173")),
		CMKKMSURI:            strings.TrimSpace(os.Getenv("KSEAL_CMK_KMS_URI")),
		CMKKMSAuthToken:      os.Getenv("KSEAL_CMK_KMS_AUTH_TOKEN"),
		RedisCAFile:          os.Getenv("KSEAL_REDIS_CA_FILE"),
		RedisPassword:        os.Getenv("KSEAL_REDIS_PASSWORD"),
		OTLPEndpoint:         strings.TrimSpace(os.Getenv("KSEAL_OTLP_ENDPOINT")),
	}

	var err error
	if c.RedisDB, err = atoiDefault("KSEAL_REDIS_DB", 0); err != nil {
		return nil, err
	}
	if c.RedisTLS, err = boolDefault("KSEAL_REDIS_TLS", false); err != nil {
		return nil, err
	}
	if c.OTLPSampleRatio, err = floatDefault("KSEAL_OTLP_SAMPLE_RATIO", 1.0); err != nil {
		return nil, err
	}
	if c.OTLPInsecure, err = boolDefault("KSEAL_OTLP_INSECURE", true); err != nil {
		return nil, err
	}
	if c.RawRetentionDays, err = atoiDefault("KSEAL_RAW_RETENTION_DAYS", 30); err != nil {
		return nil, err
	}
	if v := os.Getenv("KSEAL_NONCE_TTL"); v != "" {
		if c.NonceTTL, err = time.ParseDuration(v); err != nil {
			return nil, fmt.Errorf("KSEAL_NONCE_TTL: %w", err)
		}
	}
	if v := os.Getenv("KSEAL_TRUST_TOKEN_TTL"); v != "" {
		if c.TrustTokenTTL, err = time.ParseDuration(v); err != nil {
			return nil, fmt.Errorf("KSEAL_TRUST_TOKEN_TTL: %w", err)
		}
	}
	if v := os.Getenv("KSEAL_CONFIG_TTL"); v != "" {
		if c.ConfigTTL, err = time.ParseDuration(v); err != nil {
			return nil, fmt.Errorf("KSEAL_CONFIG_TTL: %w", err)
		}
	}
	if c.RateLimitPerSecond, err = floatDefault("KSEAL_RATE_LIMIT_RPS", c.RateLimitPerSecond); err != nil {
		return nil, err
	}
	if c.RateLimitBurst, err = atoiDefault("KSEAL_RATE_LIMIT_BURST", c.RateLimitBurst); err != nil {
		return nil, err
	}
	if c.IngestQuotaPerMinute, err = atoiDefault("KSEAL_INGEST_QUOTA_PER_MIN", c.IngestQuotaPerMinute); err != nil {
		return nil, err
	}

	c.FeatureFlags, err = parseFeatureFlags(os.Getenv("KSEAL_FEATURE_FLAGS"))
	if err != nil {
		return nil, err
	}

	if c.KEK, err = loadKEK(c.IsProd()); err != nil {
		return nil, err
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.PostgresDSN == "" {
		return errors.New("KSEAL_POSTGRES_DSN is required")
	}
	if c.RedisAddr == "" {
		return errors.New("KSEAL_REDIS_ADDR is required")
	}
	if c.HTTPAddr == "" {
		return errors.New("KSEAL_HTTP_ADDR is required")
	}
	if len(c.KEK) != 32 {
		return errors.New("resolved KEK must be 32 bytes")
	}
	if c.RateLimitBurst <= 0 || c.RateLimitPerSecond <= 0 {
		return errors.New("rate limit settings must be positive")
	}
	return nil
}

// loadKEK resolves the key-encryption key. In prod the base64 KSEAL_KEK env var
// is mandatory; otherwise a deterministic, clearly-non-secret development key is
// derived so local stacks work out of the box.
func loadKEK(isProd bool) ([]byte, error) {
	if raw := os.Getenv("KSEAL_KEK"); raw != "" {
		kek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("KSEAL_KEK base64 decode: %w", err)
		}
		if len(kek) != 32 {
			return nil, fmt.Errorf("KSEAL_KEK must decode to 32 bytes, got %d", len(kek))
		}
		return kek, nil
	}
	if isProd {
		return nil, errors.New("KSEAL_KEK is required in production environments")
	}
	// Deterministic development KEK. Never used when KSEAL_ENV is prod-like.
	dev := []byte("kseal-dev-insecure-kek-32bytes!!")
	return dev[:32], nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func atoiDefault(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func boolDefault(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func floatDefault(key string, def float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return f, nil
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
