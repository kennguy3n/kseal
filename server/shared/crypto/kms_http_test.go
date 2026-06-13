package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// kmsServer is an httptest-backed fake cloud KMS that wraps/unwraps DEKs with a
// local AES key, used to exercise the real HTTPKMSClient end to end without a
// cloud dependency.
func kmsServer(t *testing.T, requireAuth string) *httptest.Server {
	t.Helper()
	key := make([]byte, 32)
	copy(key, "fake-kms-master-key")
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/wrap", func(w http.ResponseWriter, r *http.Request) {
		if requireAuth != "" && r.Header.Get("Authorization") != "Bearer "+requireAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req kmsWrapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.KeyURI == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		pt, _ := base64.StdEncoding.DecodeString(req.Plaintext)
		// Bind the wrap to the key URI so a different URI cannot unwrap it.
		ct, err := enc.Seal(append([]byte(req.KeyURI+"|"), pt...))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(kmsWrapResponse{Ciphertext: base64.StdEncoding.EncodeToString(ct)})
	})
	mux.HandleFunc("/v1/unwrap", func(w http.ResponseWriter, r *http.Request) {
		var req kmsUnwrapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ct, _ := base64.StdEncoding.DecodeString(req.Ciphertext)
		pt, err := enc.Open(ct)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		prefix := []byte(req.KeyURI + "|")
		if !bytes.HasPrefix(pt, prefix) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(kmsUnwrapResponse{Plaintext: base64.StdEncoding.EncodeToString(pt[len(prefix):])})
	})
	return httptest.NewServer(mux)
}

func TestHTTPKMSClientRoundTrip(t *testing.T) {
	srv := kmsServer(t, "")
	defer srv.Close()
	client, err := NewHTTPKMSClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dek := bytes.Repeat([]byte{0x5a}, 32)
	wrapped, err := client.Wrap(ctx, "kms://cust/key", dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if bytes.Equal(wrapped, dek) {
		t.Fatal("wrapped DEK must not equal plaintext DEK")
	}
	got, err := client.Unwrap(ctx, "kms://cust/key", wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrap did not recover DEK")
	}
}

func TestHTTPKMSClientWrongKeyURIFails(t *testing.T) {
	srv := kmsServer(t, "")
	defer srv.Close()
	client, _ := NewHTTPKMSClient(srv.URL)
	ctx := context.Background()
	wrapped, err := client.Wrap(ctx, "kms://cust-a/key", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Unwrap(ctx, "kms://cust-b/key", wrapped); err == nil {
		t.Fatal("expected unwrap under a different key URI to fail")
	}
}

func TestHTTPKMSClientEndToEndWithManager(t *testing.T) {
	srv := kmsServer(t, "")
	defer srv.Close()
	client, _ := NewHTTPKMSClient(srv.URL)
	mgr, err := NewCMKKeyManager(newPlatformEncryptor(t), client,
		staticResolver{uris: map[string]string{"t1": "kms://cust/key"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	secret := []byte("end-to-end CMK secret")
	sealed, err := mgr.SealForTenant(ctx, "t1", secret)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := mgr.OpenForTenant(ctx, "t1", sealed)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("e2e round-trip failed: %v", err)
	}
}

func TestHTTPKMSClientAuthHeader(t *testing.T) {
	srv := kmsServer(t, "s3cr3t")
	defer srv.Close()
	ctx := context.Background()

	noAuth, _ := NewHTTPKMSClient(srv.URL)
	if _, err := noAuth.Wrap(ctx, "kms://cust/key", bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("expected 401 without auth token")
	}

	withAuth, _ := NewHTTPKMSClient(srv.URL, WithAuthToken("s3cr3t"))
	if _, err := withAuth.Wrap(ctx, "kms://cust/key", bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("wrap with auth: %v", err)
	}
}

func TestNewHTTPKMSClientRejectsEmptyEndpoint(t *testing.T) {
	if _, err := NewHTTPKMSClient("  "); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}
