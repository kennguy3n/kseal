# Chapter 4 — The trust protocol: attestation, tokens & request proofs

> **The decision:** How do you let a backend know — on *every* sensitive request — that the
> caller is a genuine, untampered app instance in a known risk state, in a way the attacker
> can't forge, replay, or lift to another device?

This is the cryptographic heart of the platform. Get it right and "owning the client" stops
being enough to abuse the backend. Get it wrong and everything above it is theater.

---

## The flow, in four RPCs

The device-plane trust flow (`server/data-plane/trust/`) is four steps:

```text
GetNonce ──► VerifyAttestation ──► (trust token) ──► ValidateRequestProof
```

1. **`GetNonce`** — the client asks for a fresh server nonce. The nonce is the anti-replay
   anchor: it ties the upcoming attestation to *this* challenge, so a captured attestation
   can't be replayed later. (`server/data-plane/trust/nonce.go`)
2. **`VerifyAttestation`** — the client binds the nonce into a platform attestation token
   (Play Integrity on Android, App Attest on iOS), adds its device-gathered risk bits, and
   submits. The server verifies the platform token, **fuses** the device signals with the
   attestation verdict, scores them against the active policy, and — if warranted — issues a
   short-lived **trust token**. (`server/data-plane/trust/service.go`, `token.go`)
3. **Trust token** — encodes *app instance identity + build hash + risk state + the nonce +
   the active policy hash*. It is signed **in-process** with a rotated key (not a per-call KMS
   operation — that's a deliberate cost choice, see [Chapter 8](08-cost-scale-and-noops-economics.md)).
4. **`ValidateRequestProof`** — on each protected API call, the client presents a per-request
   proof bound to the trust token. The server validates it before the request is honored.

The whole chain is exercised end-to-end by `tests/e2e_trust_flow_test.go`, which builds the
proof with the **same** preimage + HMAC construction the Rust SDK uses.

---

## The request proof: a canonical byte layout, or nothing

The per-request proof is the part that runs on every call, so it has to be cheap (a single
HMAC, ~333 ns — [Chapter 3](03-device-plane-rasp-and-rust-core.md)) *and* unambiguous across a
Rust producer and a Go verifier. The construction lives in
`sdk/rust-core/kseal-core/src/crypto.rs`:

```text
DOMAIN = "kseal/v1/request-proof"        // ASCII, no NUL terminator

preimage =
    u32_be(len(DOMAIN))         || DOMAIN
  || u32_be(len(token_id_utf8)) || token_id_utf8
  || u32_be(len(request_hash))  || request_hash
  || u32_be(len(nonce))         || nonce
  || i64_be(monotonic_sequence)            // fixed 8 bytes, no length prefix

tag = HMAC-SHA256(instance_key, preimage)
```

Three details that are easy to get wrong and expensive to get wrong:

- **Domain separation.** Prefixing with a constant domain string means a tag computed for one
  purpose can never be valid for another.
- **Length-prefixed framing.** Every variable-length field (`token_id`, `nonce`) is preceded
  by a 4-byte big-endian length. Without it, `token_id="ab" + nonce="c"` and
  `token_id="a" + nonce="bc"` would hash identically — a classic canonicalization attack. The
  trailing sequence is a fixed-width 8-byte big-endian `i64`, so it needs no prefix.
- **One implementation of the bytes.** The Go server recomputes this *exact* layout to verify.
  Any deviation — a different endianness, a missing prefix, a stray NUL — breaks verification.
  That's why the construction lives in the shared Rust core, not duplicated per platform.

---

## What the proof defeats (and the tests that prove it)

The instance key that signs the proof is **hardware-backed** (Android Keystore / iOS
Keychain, StrongBox / Secure Enclave where available) and never leaves the device. Combined
with the nonce and the monotonic sequence number, the proof defeats:

| Attack | Why it fails |
|---|---|
| **Replay** | The nonce is single-use and server-issued; a replayed proof carries a stale nonce |
| **Rollback** | The monotonic `sequence` must strictly increase; a decreasing sequence is rejected |
| **Token swap** | The proof binds `token_id`; the wrong token doesn't match |
| **Key lift** | The instance key is hardware-backed and non-exportable; the wrong key produces the wrong tag |
| **Repackaging** | The trust token encodes the `build_hash`; a repackaged build has a different hash |

`tests/e2e_trust_flow_test.go` asserts every one of these returns **DENY** — replayed proof,
decreasing sequence, wrong nonce, wrong token, wrong key. The proof verifies in ~444 ns
(`request_proof_verify` bench), so this protection is effectively free on the hot path.

---

## Signed config: the same idea, the other direction

Trust flows *up* (device → server). Policy flows *down* (server → device) over the **same kind
of construction**: an Ed25519-signed config envelope (`sdk/rust-core/kseal-core/src/config.rs`)
with its own domain-separated preimage. The device verifies the signature
(`config_verify_and_decode_ed25519`, ~49 µs) before trusting any policy change, and caches by
ETag with a TTL. `tests/e2e_config_test.go` covers verify + `If-None-Match` caching + TTL +
version rotation.

This is why the [GameForge kill switch](../showcase/03-gameforge-incident-response.md) and the
[ShopSwift canary](../showcase/05-shopswift-release-engineer.md) are trustworthy: the client
*verifies the signature before honoring* a "stand down" or a policy swap, so an attacker can't
forge or replay control-plane state onto a device.

---

## The business read

- **This is the part that's actually un-bypassable**, and it's the line you sell. "We don't
  ask the client to be honest about whether it's trustworthy; we make the client *prove* it to
  a server that owns the keys" is a claim you can defend to a CISO — and back with tests.
- **The cost of the protection is nanoseconds**, so there's no UX or battery objection to
  answer. That matters: the most common reason security SDKs get removed is performance, not
  efficacy.
- **In-process token signing (not per-call KMS) is a margin decision.** A naive "KMS sign per
  token" design would cost thousands/month at scale; doing it in-process with rotated keys is
  what keeps the unit economics in [Chapter 8](08-cost-scale-and-noops-economics.md) viable.

Next: [Chapter 5 — The data plane](05-data-plane-ingest-fleet-and-risk.md), where individual
decisions become *population* intelligence without a data lake or an analyst.
