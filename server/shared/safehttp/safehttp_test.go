package safehttp

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// Real, globally routable addresses must stay reachable.
	public := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
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
		"192.0.2.1",       // TEST-NET-1 (RFC 5737)
		"198.51.100.1",    // TEST-NET-2 (RFC 5737)
		"203.0.113.10",    // TEST-NET-3 (RFC 5737) — was previously asserted public
		"198.18.0.1",      // benchmarking 198.18.0.0/15 (RFC 2544), low end
		"198.19.255.255",  // benchmarking 198.18.0.0/15 (RFC 2544), high end
		"192.88.99.1",     // 6to4 relay anycast (RFC 7526)
		"2001:db8::1",     // IPv6 documentation 2001:db8::/32 (RFC 3849)
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

// TestProxyOptIn proves egress proxying is off by default and that WithProxy
// wires the caller's proxy func into the transport's request path. The stub
// returns an error so the request short-circuits before any dial, keeping the
// test deterministic and free of real network access.
func TestProxyOptIn(t *testing.T) {
	// Default: no proxy, behaviour unchanged from a direct-dial transport.
	if tr := NewTransport(); tr.Proxy != nil {
		t.Fatal("NewTransport() must not set a proxy by default")
	}
	if tr, ok := Client(time.Second).Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatal("Client(timeout) must not set a proxy by default")
	}

	// Opt-in: WithProxy installs the func and the transport consults it.
	sentinel := errors.New("stub proxy consulted")
	var seen *url.URL
	stub := func(r *http.Request) (*url.URL, error) {
		seen = r.URL
		return nil, sentinel
	}

	tr := NewTransport(WithProxy(stub))
	if tr.Proxy == nil {
		t.Fatal("WithProxy must set transport.Proxy")
	}

	c := &http.Client{Transport: tr}
	resp, err := c.Get("http://destination.example.com/path")
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected the proxy func to be consulted (sentinel error), got %v", err)
		}
	} else {
		_ = resp.Body.Close()
	}
	if seen == nil || seen.Host != "destination.example.com" {
		t.Fatalf("proxy func saw unexpected request URL: %v", seen)
	}

	// Opt-in also propagates through the Client wrapper.
	ct, ok := Client(time.Second, WithProxy(stub)).Transport.(*http.Transport)
	if !ok || ct.Proxy == nil {
		t.Fatal("Client(timeout, WithProxy(...)) must propagate the proxy to its transport")
	}
}

// TestProxyDialReachesPrivateProxy proves the opt-in path actually works for its
// primary use case: an egress proxy on a private/loopback address. The dial-time
// IP guard (which TestClientBlocksLoopback shows rejects loopback) must allow
// the proxy's own address through, otherwise the proxy itself is unreachable.
func TestProxyDialReachesPrivateProxy(t *testing.T) {
	var seenHost string
	// httptest binds to loopback (127.0.0.1), a non-public address the guard
	// blocks for direct dials — here it stands in for an internal egress proxy.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	// The destination host is never resolved or dialed by the client: for HTTP
	// proxying the absolute URL is sent to the proxy, so only the loopback proxy
	// is dialed. Without the guard bypass this fails with ErrBlockedAddress.
	c := Client(2*time.Second, WithProxy(http.ProxyURL(proxyURL)))
	resp, err := c.Get("http://destination.example.com/path")
	if err != nil {
		t.Fatalf("request through private-address proxy failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 from proxy, got %d", resp.StatusCode)
	}
	if seenHost != "destination.example.com" {
		t.Fatalf("proxy saw unexpected destination Host: %q", seenHost)
	}
}

// TestProxyNilFallbackStillGuardsDirectDial proves the guard stays active for
// direct dials even when a proxy func is configured. A proxy func returning nil
// means "dial directly" (the http.ProxyFromEnvironment + NO_PROXY case); such a
// dial to a private/loopback destination must still be blocked, otherwise a
// tenant URL could reach internal addresses via the no-proxy fallback.
func TestProxyNilFallbackStillGuardsDirectDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// A proxy func that always returns nil routes every request to a direct
	// dial — the proxy address allow-list stays empty, so the guard applies.
	var consulted bool
	direct := func(*http.Request) (*url.URL, error) {
		consulted = true
		return nil, nil
	}

	c := Client(2*time.Second, WithProxy(direct))
	resp, err := c.Get(srv.URL) // srv.URL is a loopback (non-public) address
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("expected direct dial under nil-proxy fallback to be blocked, got status %d", resp.StatusCode)
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress for guarded direct dial, got %v", err)
	}
	if !consulted {
		t.Fatal("proxy func was never consulted")
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed: got status %d, want 302", resp.StatusCode)
	}
}
