# Egress hardening

kseal makes outbound HTTP(S) calls to **tenant-controlled** destinations in two
places: webhook deliveries (`server/data-plane/webhook`) and SIEM connector
exports (`server/data-plane/siem`). In both, a tenant supplies the destination
URL. Without a guard, a tenant could point the server at addresses the server
can reach but the tenant cannot — cloud instance metadata
(`169.254.169.254`), the loopback interface, or RFC1918/ULA private ranges —
turning kseal into a confused deputy (server-side request forgery, SSRF).

All of this lives in one small, dependency-free package,
`server/shared/safehttp`, so the two egress paths share exactly one hardened
HTTP client and cannot drift apart. This document covers two behaviors that are
easy to misread from the call sites alone:

1. redirects are **not followed**, and a 3xx is a delivery *failure*; and
2. egress is **direct-dial with no proxy by default**, with an opt-in for
   deployments that front all egress through an egress proxy.

## What the guard blocks

`safehttp` enforces network policy in two layers:

- `ValidateURL` rejects non-HTTP(S) schemes (`file://`, `gopher://`, `ftp://`,
  …) and host-less URLs at configuration time. It is cheap and deterministic
  but deliberately does **not** resolve DNS, so it is necessary, not sufficient.
- `Client` / `NewTransport` return an HTTP client whose dialer resolves the host
  and refuses to connect when **any** resolved address is non-public, then dials
  one of the validated IPs directly. Because the check runs against the exact
  address the socket connects to, it closes the DNS-rebinding hole a parse-time
  hostname check leaves open.

`IsPublicIP` treats the following as non-public (not exhaustive — see the source
for the authoritative list): loopback, unspecified, link-local (covering the
`169.254.169.254` metadata endpoint), multicast, RFC1918/ULA private,
carrier-grade NAT (`100.64.0.0/10`), IETF protocol assignments
(`192.0.0.0/24`), the RFC 5737 documentation ranges TEST-NET-1/2/3
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 2544 benchmarking
(`198.18.0.0/15`), the RFC 7526 6to4 relay anycast prefix (`192.88.99.0/24`),
and the RFC 3849 IPv6 documentation prefix (`2001:db8::/32`). None of these are
routable on the public internet, so a tenant URL resolving to one is not a real
external endpoint and is refused at dial time with `ErrBlockedAddress`.

## Redirects are not followed (3xx is a delivery failure)

The client sets `CheckRedirect` to return `http.ErrUseLastResponse`, so a 3xx
response is handed back to the caller **as-is** and is never followed. This is
deliberate: following redirects would let a public, allowed endpoint bounce the
request onto an internal one (`Location: http://169.254.169.254/…`) *after* the
dial-time IP guard has already passed, reopening the SSRF hole the guard closes.

Because the redirect is not followed, the delivery paths see a 3xx status and —
since it is not 2xx — treat it as a **failure**, never a success:

- **Webhook** (`dispatcher.go`): delivery counts as successful only when
  `200 <= status < 300`. A 3xx is recorded as a failed attempt and is subject to
  the per-webhook circuit breaker and retry policy.
- **SIEM** (`exporter.go`, `classify`): only `2xx` is `resultSuccess`. `408`,
  `429`, and `5xx` are retryable; everything else — **including any 3xx** —
  classifies as `resultPermanent` and is dead-lettered rather than retried.

Operational implication: a webhook or SIEM endpoint that answers with a redirect
(e.g. `http://` → `https://`, or a load-balancer bounce) will be treated as
failing. Register the **final** URL the endpoint actually serves on, so delivery
lands a 2xx directly.

## No proxy by default; opt-in egress proxy

By default the transport sets **no** `Proxy`: kseal dials destinations directly.
This is what makes the dial-time IP guard authoritative — the guard can only
vet the real target IP when this process is the one connecting to it.

Some deployments instead funnel **all** outbound traffic through a dedicated
egress proxy (for centralized allow-listing, logging, or because direct egress
is firewalled off). For those, `safehttp` exposes an opt-in:

```go
// Default — direct dial, in-process IP guard authoritative.
client := safehttp.Client(timeout)

// Opt in to an egress proxy. The signature mirrors http.Transport.Proxy.
client := safehttp.Client(timeout, safehttp.WithProxy(http.ProxyURL(proxyURL)))

// WithProxy also accepts any func(*http.Request) (*url.URL, error), e.g.
// http.ProxyFromEnvironment to honor HTTP_PROXY/HTTPS_PROXY/NO_PROXY.
client := safehttp.Client(timeout, safehttp.WithProxy(http.ProxyFromEnvironment))
```

`WithProxy(nil)` is a no-op and keeps the direct-dial default, so existing
callers (`safehttp.Client(timeout)`) are unchanged.

### Security trade-off when a proxy is set

When a proxy is configured, this process connects to the **proxy**, not the
resolved destination. The dial-time IP guard (`guardedDialContext` /
`IsPublicIP`) therefore only ever sees the proxy's address — it no longer
observes the real target and **cannot block private destinations**. Egress
policy then lives at the proxy.

Because of this, a proxied transport **disables** the in-process IP guard
entirely (it dials via a plain `net.Dialer`). This is deliberate: an internal
egress proxy almost always listens on a private/RFC1918 (or loopback) address,
which the guard would otherwise reject as non-public — so leaving the guard
enabled would make `WithProxy` unusable for its primary deployment. The guard
adds no security in proxy mode anyway, since it cannot see past the proxy.

So if you opt in, the proxy must enforce the SSRF policy that the in-process
guard otherwise provides — e.g. an allow-listing forward proxy that refuses
internal/metadata destinations. Leaving the proxy unset (the default) keeps the
in-process guard authoritative and is the recommended posture unless your
network design specifically requires a proxy.
