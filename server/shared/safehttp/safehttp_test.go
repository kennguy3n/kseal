package safehttp

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateURL(t *testing.T) {
	ok := []string{
		"https://hooks.example.com/ingest",
		"http://splunk.internal-name:8088/services/collector",
		"https://1.2.3.4/path", // a public literal passes parse-time validation
	}
	for _, u := range ok {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", u, err)
		}
	}

	bad := []string{
		"",                     // empty
		"ftp://example.com",    // wrong scheme
		"file:///etc/passwd",   // wrong scheme
		"gopher://example.com", // wrong scheme
		"https://",             // no host
		"://nohost",            // unparseable scheme
		"http://[::1",          // malformed
	}
	for _, u := range bad {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error", u)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	public := []string{"1.1.1.1", "8.8.8.8", "203.0.113.10", "2606:4700:4700::1111"}
	for _, s := range public {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = false, want true", s)
		}
	}

	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback v6
		"0.0.0.0",         // unspecified
		"169.254.169.254", // link-local / cloud metadata
		"10.0.0.5",        // RFC1918
		"172.16.0.1",      // RFC1918
		"192.168.1.1",     // RFC1918
		"100.64.0.1",      // carrier-grade NAT
		"192.0.0.1",       // IETF reserved
		"fd00::1",         // ULA
		"fe80::1",         // link-local v6
		"224.0.0.1",       // multicast
	}
	for _, s := range blocked {
		if IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = true, want false", s)
		}
	}
	if IsPublicIP(nil) {
		t.Error("IsPublicIP(nil) = true, want false")
	}
}

// TestClientBlocksLoopback proves the dialer refuses to connect to a loopback
// httptest server even though it is reachable — the SSRF guard in action.
func TestClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := Client(2 * time.Second)
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("expected loopback dial to be blocked, got status %d", resp.StatusCode)
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got %v", err)
	}
}

// TestClientDoesNotFollowRedirects proves a public endpoint cannot bounce the
// client onto another location (the building block of redirect-based SSRF).
func TestClientDoesNotFollowRedirects(t *testing.T) {
	// Use the injected client against a loopback test server by swapping in a
	// permissive transport, so we isolate the redirect policy from the IP guard.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	c := Client(2 * time.Second)
	c.Transport = srv.Client().Transport // permissive transport, keep CheckRedirect
	resp, err := c.Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed: got status %d, want 302", resp.StatusCode)
	}
}
