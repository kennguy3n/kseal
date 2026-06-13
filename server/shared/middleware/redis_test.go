package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestBuildRedisOptionsDefaultsPlaintext(t *testing.T) {
	opts, err := buildRedisOptions(RedisConfig{Addr: "localhost:6379", DB: 1})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Addr != "localhost:6379" || opts.DB != 1 {
		t.Fatalf("addr/db not propagated: %+v", opts)
	}
	if opts.TLSConfig != nil {
		t.Fatal("TLS must be off by default for backward compatibility")
	}
	if opts.Password != "" {
		t.Fatal("password must be empty by default")
	}
}

func TestBuildRedisOptionsPassword(t *testing.T) {
	opts, err := buildRedisOptions(RedisConfig{Addr: "h:6379", Password: "s3cr3t"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Password != "s3cr3t" {
		t.Fatalf("password = %q", opts.Password)
	}
}

func TestBuildRedisOptionsTLSSystemRoots(t *testing.T) {
	opts, err := buildRedisOptions(RedisConfig{Addr: "h:6379", TLS: true})
	if err != nil {
		t.Fatal(err)
	}
	if opts.TLSConfig == nil {
		t.Fatal("expected TLS config when TLS enabled")
	}
	if opts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("min TLS version = %x", opts.TLSConfig.MinVersion)
	}
	if opts.TLSConfig.RootCAs != nil {
		t.Fatal("no CA file means system roots (nil RootCAs)")
	}
}

func TestBuildRedisOptionsTLSWithCAFile(t *testing.T) {
	caPath := writeTestCA(t)
	opts, err := buildRedisOptions(RedisConfig{Addr: "h:6379", TLS: true, CAFile: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if opts.TLSConfig == nil || opts.TLSConfig.RootCAs == nil {
		t.Fatal("expected custom RootCAs from CA file")
	}
}

func TestBuildRedisOptionsBadCAFile(t *testing.T) {
	if _, err := buildRedisOptions(RedisConfig{Addr: "h:6379", TLS: true, CAFile: "/nonexistent/ca.pem"}); err == nil {
		t.Fatal("expected error for missing CA file")
	}

	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildRedisOptions(RedisConfig{Addr: "h:6379", TLS: true, CAFile: empty}); err == nil {
		t.Fatal("expected error for CA file with no valid certs")
	}
}

func TestNewRedisAuthEndToEnd(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("s3cr3t")
	ctx := context.Background()

	// Correct password authenticates and pings successfully.
	client, err := NewRedis(ctx, RedisConfig{Addr: mr.Addr(), Password: "s3cr3t"})
	if err != nil {
		t.Fatalf("expected AUTH to succeed: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Wrong/empty password is rejected by the server on ping.
	if _, err := NewRedis(ctx, RedisConfig{Addr: mr.Addr(), Password: "wrong"}); err == nil {
		t.Fatal("expected AUTH failure with wrong password")
	}
}

// writeTestCA emits a self-signed CA certificate to a temp file and returns its
// path, used to validate CA-file loading without a real CA.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kseal-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}
