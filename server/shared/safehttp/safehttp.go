// Package safehttp provides SSRF-hardened HTTP egress for the calls kseal makes
// to tenant-controlled destinations: webhook deliveries and SIEM connector
// exports. In both cases a tenant supplies the destination URL, so without a
// guard a tenant could point the server at addresses it can reach but the
// tenant cannot — cloud instance metadata (169.254.169.254), the loopback
// interface, or RFC1918/ULA private ranges — turning kseal into a confused
// deputy (server-side request forgery).
//
// Enforcement has two layers:
//
//   - ValidateURL rejects non-HTTP(S) schemes and host-less URLs at
//     configuration time. It is cheap and deterministic but cannot resolve DNS,
//     so it is necessary, not sufficient.
//   - Client returns an *http.Client whose dialer resolves the host and refuses
//     to connect when any resolved address is non-public, then dials one of the
//     validated IPs directly. Because the check runs against the exact address
//     the socket connects to, it closes the DNS-rebinding hole a parse-time
//     hostname check leaves open. Redirects are not followed, so a public
//     endpoint cannot bounce the request onto an internal one.
//
// Egress proxying is off by default. A caller that fronts all outbound traffic
// with an egress proxy can opt in via WithProxy; see that option for the
// security trade-off (the dial-time IP guard no longer sees the real target).
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrBlockedAddress is returned by the dialer when a destination resolves to a
// non-public address.
var ErrBlockedAddress = errors.New("safehttp: destination resolves to a non-public address")

// ValidateURL reports whether raw is a well-formed absolute HTTP(S) URL with a
// host. It deliberately does not resolve DNS or reject private literals: the
// authoritative network-policy check is the dialer returned by Client, which
// inspects the resolved IP at connect time (DNS-rebinding safe). Keeping
// configuration-time validation DNS-free makes it fast and deterministic while
// still rejecting never-valid schemes such as file://, gopher://, or ftp://.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("safehttp: invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("safehttp: url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("safehttp: url must include a host")
	}
	return nil
}

// Option customises the Client/NewTransport defaults. The defaults are the
// hardened ones (direct dial, resolved-IP guard, no proxy); options are purely
// additive, so the zero set of options preserves the original behaviour.
type Option func(*config)

// config holds the resolved option values for a Client/Transport.
type config struct {
	// proxy mirrors http.Transport.Proxy: nil means dial destinations
	// directly (the default), which is the only mode in which the dial-time
	// IP guard is authoritative.
	proxy func(*http.Request) (*url.URL, error)
}

// WithProxy routes egress through the proxy URL selected by fn, mirroring
// http.Transport.Proxy (return a nil *url.URL to dial a given request directly).
// Passing fn == nil is a no-op and keeps the direct-dial default.
//
// Security trade-off: with a proxy set, this process connects to the proxy
// rather than the resolved destination, so the dial-time IP guard
// (guardedDialContext / IsPublicIP) no longer observes the real target address
// and cannot block private destinations. The guard is therefore disabled on a
// proxied transport — otherwise it would reject the proxy's own (typically
// private) address. When you opt in, egress policy must be enforced at the
// proxy instead (e.g. an allowlisting forward proxy). Leave it unset to keep
// the in-process SSRF guard authoritative.
func WithProxy(fn func(*http.Request) (*url.URL, error)) Option {
	return func(c *config) { c.proxy = fn }
}

func newConfig(opts []Option) config {
	var cfg config
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// Client returns an *http.Client safe for fetching tenant-controlled URLs. A
// timeout of 0 leaves the client-level timeout unset for callers that bound
// each attempt with a per-request context deadline instead. Redirects are not
// followed, and every dial is gated by the resolved-IP check. With no options
// the client dials destinations directly; see WithProxy to opt into an egress
// proxy.
func Client(timeout time.Duration, opts ...Option) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: NewTransport(opts...),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NewTransport builds an *http.Transport whose DialContext rejects connections
// to non-public addresses. By default it sets no Proxy: the IP guard is only
// authoritative when this process dials the destination directly, since routing
// through a proxy would hide the real target IP from the guard. Pass WithProxy
// to opt into an egress proxy, accepting that trade-off.
func NewTransport(opts ...Option) *http.Transport {
	cfg := newConfig(opts)
	base := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	// With a proxy configured, http.Transport invokes DialContext to reach the
	// proxy (often a private/RFC1918 host) rather than the destination, so the
	// resolved-IP guard would reject the proxy itself and can no longer observe
	// the real target anyway. Egress policy then lives at the proxy, so dial it
	// directly; otherwise keep the in-process guard authoritative. See
	// docs/egress-hardening.md.
	dial := guardedDialContext(base)
	if cfg.proxy != nil {
		dial = base.DialContext
	}
	return &http.Transport{
		Proxy:                 cfg.proxy,
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// guardedDialContext resolves the host, refuses the dial if any resolved
// address is non-public, then connects to one of the validated IPs directly so
// the connection cannot race a re-resolution to a different (internal) address.
// TLS verification still uses the original hostname: the transport derives the
// ServerName from the request URL, independent of the IP we connect to.
func guardedDialContext(d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// LookupIP returns IP literals unchanged (no DNS), so this also handles
		// hosts that are already addresses.
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		// Require every resolved address to be public: a resolver that returns a
		// mix of public and private answers (a rebinding trick) must not be
		// dialable at all.
		for _, ip := range ips {
			if !IsPublicIP(ip) {
				return nil, ErrBlockedAddress
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, derr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if derr != nil {
				lastErr = derr
				continue
			}
			return conn, nil
		}
		if lastErr == nil {
			lastErr = ErrBlockedAddress
		}
		return nil, lastErr
	}
}

// IsPublicIP reports whether ip is a globally routable unicast address — i.e.
// not loopback, unspecified, link-local (which covers the 169.254.169.254 cloud
// metadata endpoint), multicast, RFC1918/ULA private, carrier-grade NAT
// (100.64.0.0/10), IETF-reserved (192.0.0.0/24), the RFC 5737 documentation
// ranges TEST-NET-1/2/3 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
// RFC 2544 benchmarking (198.18.0.0/15), the RFC 7526 6to4 relay anycast
// prefix (192.88.99.0/24), or the RFC 3849 IPv6 documentation prefix
// (2001:db8::/32). These ranges are non-routable on the public internet, so a
// tenant URL that resolves to one is treated as an attempt to reach something
// other than a real external endpoint.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 100 && v4[1] >= 64 && v4[1] < 128: // 100.64.0.0/10 carrier-grade NAT (RFC 6598)
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24 IETF protocol assignments (RFC 6890)
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2: // 192.0.2.0/24 TEST-NET-1 documentation (RFC 5737)
			return false
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100: // 198.51.100.0/24 TEST-NET-2 documentation (RFC 5737)
			return false
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // 203.0.113.0/24 TEST-NET-3 documentation (RFC 5737)
			return false
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19): // 198.18.0.0/15 benchmarking (RFC 2544)
			return false
		case v4[0] == 192 && v4[1] == 88 && v4[2] == 99: // 192.88.99.0/24 6to4 relay anycast (RFC 7526)
			return false
		}
		return true
	}
	// IPv6-only ranges the stdlib predicates above don't cover, mirroring the
	// IPv4 documentation ranges for defense-in-depth consistency.
	if v6 := ip.To16(); v6 != nil {
		// 2001:db8::/32 documentation prefix (RFC 3849).
		if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8 {
			return false
		}
	}
	return true
}
