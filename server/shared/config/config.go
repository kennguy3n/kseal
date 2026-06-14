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

	// DedicatedIsolation enables the dedicated/regulated isolation tier
	// (KSEAL_DEDICATED_ISOLATION). When off (default) every tenant uses the
	// shared logical isolation under the platform KEK (unchanged behavior). When
	// on, tenants flagged dedicated_isolation (and without a customer-managed
	// key) get a per-tenant HKDF-derived key domain.
	DedicatedIsolation bool

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

	// DataPlane holds the default-off production data-plane backend selection
	// (broker + analytics store). The zero value keeps the in-memory MVP.
	DataPlane DataPlaneConfig
}

// DataPlaneConfig selects and configures the data-plane backends. Both backends
// default to the in-memory MVP; selecting "kafka"/"clickhouse" requires the
// matching connection envs and fails closed (clear error) if they are missing.
type DataPlaneConfig struct {
	// Broker is "memory" (default) or "kafka".
	Broker string
	// Analytics is "memory" (default) or "clickhouse".
	Analytics string

	// Kafka/Redpanda broker connection (used when Broker == "kafka").
	KafkaBrokers            []string
	KafkaTopic              string
	KafkaConsumerGroup      string
	KafkaTLS                bool
	KafkaCAFile             string
	KafkaInsecureSkipVerify bool
	KafkaSASLMechanism      string
	KafkaSASLUsername       string
	KafkaSASLPassword       string

	// ClickHouse analytics connection (used when Analytics == "clickhouse").
	ClickHouseAddr               []string
	ClickHouseDatabase           string
	ClickHouseUsername           string
	ClickHousePassword           string
	ClickHouseTable              string
	ClickHouseCluster            string
	ClickHouseRetentionTTLDays   int
	ClickHouseTLS                bool
	ClickHouseCAFile             string
	ClickHouseInsecureSkipVerify bool
}

// UsesKafka reports whether the Kafka broker backend is selected.
func (d DataPlaneConfig) UsesKafka() bool { return strings.EqualFold(d.Broker, "kafka") }

// UsesClickHouse reports whether the ClickHouse analytics backend is selected.
func (d DataPlaneConfig) UsesClickHouse() bool { return strings.EqualFold(d.Analytics, "clickhouse") }

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
	if c.DedicatedIsolation, err = boolDefault("KSEAL_DEDICATED_ISOLATION", false); err != nil {
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

	if err := c.loadDataPlane(); err != nil {
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

// loadDataPlane parses the default-off data-plane backend selection. Unknown
// selectors and selected-but-unconfigured backends fail closed with a clear
// error, so a misconfigured production server refuses to start rather than
// silently degrading to in-memory (which would lose telemetry on restart).
func (c *Config) loadDataPlane() error {
	d := DataPlaneConfig{
		Broker:             strings.ToLower(getenv("KSEAL_BROKER", "memory")),
		Analytics:          strings.ToLower(getenv("KSEAL_ANALYTICS", "memory")),
		KafkaBrokers:       splitNonEmpty(os.Getenv("KSEAL_KAFKA_BROKERS")),
		KafkaTopic:         strings.TrimSpace(os.Getenv("KSEAL_KAFKA_TOPIC")),
		KafkaConsumerGroup: strings.TrimSpace(os.Getenv("KSEAL_KAFKA_CONSUMER_GROUP")),
		KafkaCAFile:        strings.TrimSpace(os.Getenv("KSEAL_KAFKA_CA_FILE")),
		KafkaSASLMechanism: strings.ToLower(strings.TrimSpace(os.Getenv("KSEAL_KAFKA_SASL_MECHANISM"))),
		KafkaSASLUsername:  os.Getenv("KSEAL_KAFKA_SASL_USERNAME"),
		KafkaSASLPassword:  os.Getenv("KSEAL_KAFKA_SASL_PASSWORD"),
		ClickHouseAddr:     splitNonEmpty(os.Getenv("KSEAL_CLICKHOUSE_ADDR")),
		ClickHouseDatabase: strings.TrimSpace(os.Getenv("KSEAL_CLICKHOUSE_DATABASE")),
		ClickHouseUsername: os.Getenv("KSEAL_CLICKHOUSE_USERNAME"),
		ClickHousePassword: os.Getenv("KSEAL_CLICKHOUSE_PASSWORD"),
		ClickHouseTable:    strings.TrimSpace(os.Getenv("KSEAL_CLICKHOUSE_TABLE")),
		ClickHouseCluster:  strings.TrimSpace(os.Getenv("KSEAL_CLICKHOUSE_CLUSTER")),
	}

	var err error
	if d.KafkaTLS, err = boolDefault("KSEAL_KAFKA_TLS", false); err != nil {
		return err
	}
	if d.KafkaInsecureSkipVerify, err = boolDefault("KSEAL_KAFKA_INSECURE_SKIP_VERIFY", false); err != nil {
		return err
	}
	if d.ClickHouseTLS, err = boolDefault("KSEAL_CLICKHOUSE_TLS", false); err != nil {
		return err
	}
	if d.ClickHouseInsecureSkipVerify, err = boolDefault("KSEAL_CLICKHOUSE_INSECURE_SKIP_VERIFY", false); err != nil {
		return err
	}
	// Default the ClickHouse TTL backstop to the platform raw-retention window so
	// the coarse table TTL and the precise per-tenant purge stay aligned.
	if d.ClickHouseRetentionTTLDays, err = atoiDefault("KSEAL_CLICKHOUSE_RETENTION_TTL_DAYS", c.RawRetentionDays); err != nil {
		return err
	}

	switch d.Broker {
	case "memory":
	case "kafka":
		if len(d.KafkaBrokers) == 0 {
			return errors.New("KSEAL_BROKER=kafka requires KSEAL_KAFKA_BROKERS")
		}
	default:
		return fmt.Errorf("KSEAL_BROKER must be 'memory' or 'kafka', got %q", d.Broker)
	}

	switch d.Analytics {
	case "memory":
	case "clickhouse":
		if len(d.ClickHouseAddr) == 0 {
			return errors.New("KSEAL_ANALYTICS=clickhouse requires KSEAL_CLICKHOUSE_ADDR")
		}
	default:
		return fmt.Errorf("KSEAL_ANALYTICS must be 'memory' or 'clickhouse', got %q", d.Analytics)
	}

	c.DataPlane = d
	return nil
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
