package middleware

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig captures the connection settings for the shared Redis client.
// Defaults (no TLS, no AUTH) are fully backward-compatible with plaintext
// local/dev Redis; production hardens the link via TLS and AUTH.
type RedisConfig struct {
	Addr     string
	DB       int
	Password string
	// TLS enables an encrypted connection to Redis.
	TLS bool
	// CAFile, when set, is a PEM bundle used to verify the Redis server
	// certificate. Empty uses the host's system roots.
	CAFile string
}

// buildRedisOptions translates a RedisConfig into go-redis options, including
// the TLS config and AUTH credential. It is pure (no network I/O) so the
// option-construction logic is unit-testable without a live Redis.
func buildRedisOptions(cfg RedisConfig) (*redis.Options, error) {
	opts := &redis.Options{
		Addr:         cfg.Addr,
		DB:           cfg.DB,
		Password:     cfg.Password,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolSize:     20,
	}
	if cfg.TLS {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read redis CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("redis CA file %q contained no valid certificates", cfg.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		opts.TLSConfig = tlsCfg
	}
	return opts, nil
}

// NewRedis creates and pings a go-redis client from cfg.
func NewRedis(ctx context.Context, cfg RedisConfig) (*redis.Client, error) {
	opts, err := buildRedisOptions(cfg)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return client, nil
}
