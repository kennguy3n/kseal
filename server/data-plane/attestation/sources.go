package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

// googleJWKSURL is Google's public JWKS endpoint used to verify Play Integrity
// token signatures. Fetching from it is the single external dependency for
// Android attestation; it is mocked in tests via a static KeySource.
const googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// appleRootEnv optionally provides the Apple App Attest root CA (PEM, inline or a
// file path). Apple's root is external trust material; tests inject a locally
// generated root instead.
const appleRootEnv = "KSEAL_APPLE_ATTEST_ROOT_PEM"

// HTTPJWKSKeySource fetches and caches JWKS public keys by key id.
type HTTPJWKSKeySource struct {
	url    string
	client *http.Client
	ttl    time.Duration

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// NewHTTPJWKSKeySource builds a JWKS key source.
func NewHTTPJWKSKeySource(url string) *HTTPJWKSKeySource {
	return &HTTPJWKSKeySource{
		url:    url,
		client: &http.Client{Timeout: 5 * time.Second},
		ttl:    time.Hour,
		keys:   map[string]crypto.PublicKey{},
	}
}

// GoogleProductionKeys returns a JWKS source bound to Google's endpoint.
func GoogleProductionKeys() *HTTPJWKSKeySource { return NewHTTPJWKSKeySource(googleJWKSURL) }

// PublicKey returns the key for keyID, refreshing the JWKS cache on miss or when
// the cache has expired.
func (s *HTTPJWKSKeySource) PublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	s.mu.RLock()
	key, ok := s.keys[keyID]
	fresh := time.Since(s.fetchedAt) < s.ttl
	s.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}
	if err := s.refresh(ctx); err != nil {
		if ok {
			return key, nil // serve stale rather than fail closed on a transient error
		}
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if key, ok := s.keys[keyID]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("attestation: unknown jwks key id %q", keyID)
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (s *HTTPJWKSKeySource) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("attestation: jwks fetch status %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	s.mu.Lock()
	s.keys = keys
	s.fetchedAt = time.Now()
	s.mu.Unlock()
	return nil
}

func (k jwkKey) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if e == 0 {
			e = int(binary.BigEndian.Uint32(append(make([]byte, 4-len(eb)), eb...)))
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
	case "EC":
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
	default:
		return nil, fmt.Errorf("unsupported jwk kty %q", k.Kty)
	}
}

// AppleProductionRoots builds the Apple App Attest root pool from the
// KSEAL_APPLE_ATTEST_ROOT_PEM env var (inline PEM or a file path). When unset it
// returns an empty pool so App Attest verification fails closed rather than
// trusting an unknown root.
func AppleProductionRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	raw := os.Getenv(appleRootEnv)
	if raw == "" {
		return pool
	}
	pemBytes := []byte(raw)
	if _, err := pem.Decode(pemBytes); err == nil {
		pool.AppendCertsFromPEM(pemBytes)
		return pool
	}
	if data, err := os.ReadFile(raw); err == nil {
		pool.AppendCertsFromPEM(data)
	}
	return pool
}

// NewProductionVerifier wires the production Android + iOS verifiers.
func NewProductionVerifier() *Verifier {
	return NewVerifier(
		NewPlayIntegrityVerifier(GoogleProductionKeys()),
		NewAppAttestVerifier(AppleProductionRoots()),
	)
}
