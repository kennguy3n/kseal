# The kseal blog

Deep-dives into how kseal works, written against the canonical reference
customer **Meridian Pay** (tenant `meridian`, apps `pay-android` + `merchant`).
Every number is measured or taken from source — the
[reference docs](https://github.com/kennguy3n/kseal/tree/main/docs/reference)
hold the fixtures and benchmarks each post cites.

---

## [Why the trust decision lives on the server](trust-on-the-server.md)

The whole product thesis in one idea: the client gathers evidence, but the
**server** decides. We walk a repackaged Meridian Pay build through fusion and
scoring to show why a tampered phone still can't talk its way past the backend.

## [Inside the risk engine: 21 wire bits, 17 server signals](inside-the-risk-engine.md)

The device reports a packed bitset; the server translates it through `FromWire`,
fuses in attestation-derived signals, and scores with saturating addition
against fixed thresholds. Here's the exact contract, with weights and worked
examples.

## [Anatomy of a build proof](anatomy-of-a-build-proof.md)

What actually goes into `kseal.build-proof`, why two clean builds of the same
inputs produce a byte-identical `build_hash`, and how per-build polymorphism
makes a bypass crafted for one release decay against the next.

## [Five fraud vectors mobile payments can't ignore](five-fraud-vectors.md)

Screen-capture, overlay/tapjacking, accessibility abuse, malicious IMEs, and
remote-access scams — the abuse patterns behind real-time payment fraud, the
on-device probes that catch them, and the risk bits they raise.

---

!!! info "One customer, end to end"
    These posts deliberately reuse one deployment so the examples compose. If
    you're new here, start with **[Why the trust decision lives on the
    server](trust-on-the-server.md)**, then read the others in any order.
