# Phase 6.1 — White-Box Cryptography for the Proof Key: Decision Spike & GO/NO-GO

**Status:** Decision spike (prototype + analysis). **Not** a production rollout.
**Plan item:** 6.1 — *white-box cryptography for the proof-key path on devices
that report `SECURE_HW_MISSING` (no hardware-backed keystore), so a static dump
of the shipped `.so`/dylib does not reveal the proof key.*
**Scope of this document:** the three deliverables of the spike — (A) a bounded,
feature-gated Rust prototype, (B) this design doc, and (C) the recommendation.

---

## 1. Recommendation: **NO-GO (defer)** — do not productionize a white-box proof key now

**Do not swap the proof-key path to a white-box construction for the fleet at
this time.** Keep the capability as a documented, default-off spike. Continue to
*prefer hardware-backed keys when present*, and on `SECURE_HW_MISSING` devices
keep relying on the existing layered defenses (Phase 5.2 native string
obfuscation, Phase 4 RASP/anti-debug/anti-Frida/self-integrity, per-build
polymorphism) plus the server-side trust thesis. Revisit **only** under the
specific conditions in §8.

**Why, in one paragraph.** kseal's trust decision is **server-side**: the server
independently verifies platform attestation, the signed request proof, and the
reproducible `build_hash`. A proof key lifted from a client therefore only lets
an attacker forge *client-side* artifacts for *that* instance — it does not yield
a server-accepted trust decision, because the server still requires fresh,
genuine attestation bound to a known-good build. The spike proves the two things
worth proving cheaply: (1) **parity is real** — a table-based white-box MAC
reproduces the production proof HMAC tag *byte-for-byte* on the golden vector, so
Go↔device parity is preserved and the white-box path is a drop-in; and (2)
**static key extraction is genuinely defeated** at low cost — the raw key and
both HMAC key blocks are absent from the compiled artifact (verified by grep over
the release `rlib`), for ~32 KB of tables and ~+60 ns/tag. But the honest blocker
is what the spike *cannot* do self-contained: because the proof MAC is
**HMAC-SHA256**, a white-box that never reconstitutes the key requires
white-boxing the **SHA-256 compression function itself** (encoded message
schedule + round function) — a large, DCA/DFA-fragile effort that is realistically
a **vendor toolchain** purchase with per-key build-plane keygen and key custody.
Given the server-side-trust thesis, that marginal benefit (raising the bar on a
*dynamic* attacker who, with the current spike, can still lift the key block at
its moment of use) does not justify the build-infra and crypto-maintenance cost
today.

| | Verdict |
|---|---|
| **Recommendation** | **NO-GO (defer).** Default-off, documented, not shipped. |
| **One-line rationale** | Server-side trust makes a lifted client key low-value; a *true* self-contained white-box HMAC needs SHA-256 white-boxing (vendor-grade), and the spike's tractable form still reconstitutes the key block at use. |
| **What the spike *does* prove** | Byte-for-byte parity with the golden proof HMAC tag, and that the raw key is absent from a static binary dump, for ~32 KB / ~+60 ns/tag. |
| **Cost driver** | Build-plane per-key table generation + key custody + (for real resistance) white-boxing SHA-256 or a vendor toolchain — **not** binary size or latency. |
| **Flip to GO if** | A concrete contractual/compliance requirement demands at-rest key concealment on `SECURE_HW_MISSING` devices that the existing stack cannot satisfy (§8). |

This is consistent with kseal's existing posture (`ARCHITECTURE.md` favors
server-side trust over heavyweight client obfuscation). The spike confirms that
judgment **with measurements** rather than by assertion.

---

## 2. What was built (deliverable A) — and what is CI-validated

A bounded, **feature-gated** (`whitebox-spike`, default **off**) Rust prototype
lives entirely in the trust core at
`sdk/rust-core/kseal-core/src/whitebox/`. It is additive and isolated:

- It does **not** replace or alter the production crypto path. The shipped
  request proof is still produced by `crypto::generate_request_proof`
  (`hmac` + `sha2`); the white-box code reproduces the *same* tag a different
  way.
- It adds **nothing** to the `kseal_*` FFI C ABI.
- With the feature off, the standard build is **byte-for-byte unchanged**: the
  only edits to existing source are a single `#[cfg(feature = "whitebox-spike")]
  pub mod whitebox;` line in `lib.rs` and the feature declaration in
  `Cargo.toml`. (Verified: the default-build `libkseal_ffi.so` SHA-256 is
  identical before and after this change.)

The module has three parts:

1. **`tables.rs` — compile-time encoded key tables.** The two `HMAC-SHA256` key
   blocks `k_ipad = K' ^ ipad` and `k_opad = K' ^ opad` (where `K'` is the proof
   key zero-padded to the 64-byte block) are the only secret-bearing inputs. For
   each of the 128 key-block byte positions we generate, from a deterministic
   compile-time PRNG (SplitMix64 + Fisher–Yates with rejection sampling, all
   inside `const fn`s), a random byte bijection `S_i` (a 256-entry permutation).
   We store the **encoded** byte
   `enc_i = S_i(b_i)` and the **inverse** table `S_i^{-1}`; at runtime the
   plaintext byte is recovered as `b_i = S_i^{-1}[enc_i]`. Because the whole
   derivation runs during const-evaluation, the raw key (given as integer byte
   values, never an ASCII literal) is *consumed at compile time* and never
   emitted as a runtime symbol.
2. **`mac.rs` — the white-box keyed MAC.** It decodes the two key blocks from the
   tables and feeds them into the **vetted `sha2` crate** as
   `H((K' ^ opad) || H((K' ^ ipad) || m))`. For a key ≤ block size this is
   exactly `HMAC-SHA256(K, m)`, so the tag is byte-identical to
   `crypto::hmac_sha256`. The reconstructed key blocks are best-effort scrubbed
   (via `zeroize` — volatile writes behind a compiler fence) before returning;
   this is still only best-effort because `sha2` copies each block into its own
   internal buffer (see §3).
3. **`mod.rs` — parity surface + measurement.** `whitebox_request_proof(...)`
   builds the canonical proof preimage (mirroring `crypto::proof_preimage`'s
   domain-separated, length-prefixed layout) and signs it with the white-box
   MAC, returning a `RequestProof`. A `measure` submodule reports table size and
   per-tag latency.

**No `unsafe`. No new resolved crates** (reuses `sha2` already in the workspace;
the optional `zeroize` scrub dependency was already present in `Cargo.lock`
transitively via the `ed25519-dalek` stack, so the spike adds **no new
supply-chain surface** — the only `Cargo.lock` edit is adding the already-present
`zeroize` to `kseal-core`'s dependency list, pulled in only when the feature is
enabled). CI exercises the feature: the Makefile `test-rust`
and `lint` targets now also run `cargo test --features whitebox-spike` and
`cargo clippy --all-targets --features whitebox-spike -- -D warnings`.

### 2.1 Parity — the key deliverable (PASS)

The parity test `whitebox_proof_tag_equals_standard_and_golden` asserts, on the
project's golden vector (`token_id="tok"`, `request_hash=01 02 03 04`,
`nonce=AA BB`, `seq=1`, key `kseal-test-instance-key`):

```
whitebox_request_proof(...).app_instance_signature
  == crypto::generate_request_proof(key, ...).app_instance_signature   // standard HMAC path
  == 718bb06df45dc4bbc5bf483bd65acf7609429966adba8baff66fa965857ebd0d  // golden tag (crypto.rs)
```

byte-for-byte. It further asserts the **entire** `RequestProof` matches the
standard path (drop-in), checks parity over **3,000 random messages**
(`whitebox_hmac_matches_standard_over_random_messages`), and confirms a
white-box-produced proof is accepted by the **production verifier**
`crypto::verify_request_proof` (`whitebox_proof_verifies_with_standard_verifier`).
This is the "Go↔device parity on golden vectors" acceptance criterion: the
device-side white-box result equals exactly what the Go server independently
expects.

### 2.2 Static-extraction evidence (PASS)

Two checks back the central claim that the raw key is absent from a static dump:

- **In-code** (`encoded_tables_do_not_contain_raw_key`): the baked table blob
  contains neither the 23-byte raw key nor either reconstructed key block.
- **Over the compiled artifact**: `grep` of the release `libkseal_core.rlib`
  (built `--features whitebox-spike`, which holds all white-box code + the static
  32 KB tables) finds **0** occurrences of the raw key ASCII
  `kseal-test-instance-key`, **0** of the `k_ipad` block, and **0** of the
  `k_opad` block — while control strings (e.g. `kseal/v1/request-proof`) are
  present. The const-evaluated integer-byte key leaves no readable trace.

---

## 3. Threat model — what white-box does and does not defend

**Setting.** A device reports `SECURE_HW_MISSING`: no hardware-backed keystore,
so a conventionally-stored proof key would sit as raw bytes in the process image
and in the shipped native artifact, recoverable by `strings`/a static dump.

**What this construction defends (raises cost):**

- **Static key extraction from a binary/at-rest dump.** The contiguous key is
  not present in the artifact; recovering it requires *understanding and
  composing* the encoded tables, not a `grep`/`strings` pass. (Verified in §2.2.)

**What it does *not* fully defend (honest limits):**

- **Dynamic / memory-resident extraction.** This tractable, self-contained spike
  does **not** achieve a fully-encoded data flow: the key block is *transiently
  reconstructed on the stack at use* (then scrubbed). A determined dynamic
  attacker with a debugger/Frida on a rooted device can breakpoint the decode and
  read it. Real resistance requires the decode to be **fused into** the SHA-256
  compression so the key never reconstitutes — which the spike does not do.
- **Grey-box / table-lifting attacks.** Even a "true" white-box is not
  unbreakable. Published attacks — **DCA** (Differential Computation Analysis,
  side-channel-style on captured execution traces) and **DFA** (Differential
  Fault Analysis) — routinely break unprotected academic white-box AES, and the
  encoded tables can simply be *lifted wholesale* and replayed as an oracle.
  White-box **raises attacker cost; it is not a guarantee.**
- **Affine/structural weakness of the spike encoding.** The per-byte bijections
  are independent encodings without external (inter-table) mixing, so they are
  weaker than production white-box internal/external encodings. This is a spike
  illustrating storage concealment, not a hardened scheme.

**Why this is acceptable for kseal regardless — the server-side-trust tie-in.**
A lifted proof key only forges **client-side** artifacts for one instance. The
server independently verifies platform **attestation** and the reproducible
**`build_hash`**, and the proof is replay-protected (nonce + monotonic
sequence). So even a fully-lifted key does **not** grant a server-accepted trust
decision from an unattested or tampered client. White-box is, at best, an
incremental at-rest hardening for one risk signal — not a load-bearing control.

---

## 4. Where it applies

- **Only the proof-key path** (the request-proof HMAC). Not Ed25519 signed-config
  verification, not the kill-switch (those verify *public*-key signatures or use
  server-held keys; there is no client secret to conceal).
- **Only when a hardware keystore is unavailable** (`SECURE_HW_MISSING`).
  **Hardware-backed keys remain strictly preferred when present** — they defend
  the dynamic/memory case that white-box does not, at lower cost.
- Treated as **defense-in-depth for one risk signal**, layered under the existing
  Phase 4/5 hardening and the server-side trust decision — never as a replacement
  for attestation.

---

## 5. Perf & size budget (measured)

Measured on the spike harness (`measure::run`), release build, this VM. Latency
is wall-clock per tag, standard `HMAC-SHA256` vs white-box, averaged over 200k
iterations after warmup; timing is informational (never asserted, so CI cannot
flake).

| Message length | Standard HMAC | White-box | Absolute Δ | Tax |
|---|---|---|---|---|
| 16 B | ~218 ns | ~294 ns | ~+76 ns | ~1.35× |
| **55 B** (proof-preimage-sized) | **~220 ns** | **~283 ns** | **~+63 ns** | **~1.29×** |
| 256 B | ~377 ns | ~426 ns | ~+49 ns | ~1.13× |

**Table size:** `WHITEBOX_TABLE_BYTES = 32,896 bytes ≈ 32.1 KB` — 128 encoded
key-block bytes + 128 × 256-byte inverse permutation tables, in `.rodata`.

**Reading the numbers.** The overhead is a near-constant **~+50–75 ns/tag** (128
table lookups + scrub), so the *relative* tax shrinks as the message grows. The
proof path computes a single tag per request, far off the hot path; **+~60 ns and
~32 KB are negligible against the proof budget** and are *not* the reason for the
NO-GO. (A nibble-encoded variant would cut tables to ~4 KB; size is not the
constraint either way.) The constraint is engineering/operational, per §1 and §6.

---

## 6. Build / vendor posture — what productionizing actually requires

The spike bakes a **single, in-source** key into tables at compile time to prove
parity. A real deployment cannot ship one key to the whole fleet, and must not
keep the key in source. Productionizing requires:

1. **Build-plane per-key table generation.** A keygen step in the build/release
   plane that, per tenant/instance key, emits the encoded tables — the key must
   live only in the build plane (an HSM/KMS-fronted secret), **never in the
   repo**. This is a new, security-critical build component to own and audit.
2. **Key custody & rotation.** Table generation, storage, and rotation become
   part of key management; rotating a key means re-generating tables and shipping
   a new build. This couples crypto key lifecycle to the build pipeline.
3. **Per-build table polymorphism.** Tables (and ideally the encoding scheme)
   should differ per build so one extracted set of tables does not generalize
   across releases/fleet — mirroring the per-build polymorphism kseal already
   applies elsewhere.
4. **Real white-box strength = white-boxing SHA-256 (or a vendor toolchain).**
   To stop the key from reconstituting at use (the §3 dynamic gap), the decode
   must be fused into an **encoded SHA-256 compression** (encoded message
   schedule + round function, internal/external encodings). This is a
   substantial, attack-fragile (DCA/DFA) engineering effort that is realistically
   a **commercial white-box vendor** purchase, with the attendant licensing,
   integration, and crash-debuggability costs.

The spike deliberately stops at storage concealment with proven parity precisely
to scope what (3)/(4) would cost before committing.

---

## 7. Hard invariants honored

- **Additive + default-off**; default build byte-for-byte unchanged (verified via
  identical `libkseal_ffi.so` hash).
- **Golden vectors byte-identical**; the production proof HMAC / Ed25519 /
  kill-switch outputs are untouched. The white-box path *matches* the golden tag,
  it does not replace it.
- `kseal_*` **FFI exports unchanged**; **no** proto changes; **no** `server/**`
  or `server/gen` changes (proto-drift clean).
- **No `unsafe`; no heavy new dependencies; no new resolved crates** (the
  optional `zeroize` scrub dep was already in `Cargo.lock` transitively via the
  `ed25519-dalek` stack; the only lock edit is listing it under `kseal-core`).
- Owns its own scaffolding (new `whitebox-spike` feature, new `mod whitebox`, new
  Makefile lines); does **not** touch the `vm-spike` feature, the `vmspike`
  module, or `docs/virtualization-tier-decision.md`.

---

## 8. Conditions that would flip this to GO

Revisit and consider productionizing **only** if all of the following hold:

1. A concrete **contractual/compliance requirement** mandates at-rest concealment
   of a client key on `SECURE_HW_MISSING` devices that the existing
   string-obfuscation + RASP + server-side-trust stack demonstrably cannot
   satisfy.
2. The **build-plane keygen + key-custody + per-build polymorphism** machinery of
   §6 is funded and owned (not bolted on).
3. Either an **encoded-SHA-256 white-box** is implemented and DCA/DFA-evaluated,
   or a **vendor white-box toolchain** is licensed and integrated — i.e. the
   construction actually closes the §3 dynamic gap rather than only concealing the
   key at rest.

Absent these, the layered hardening already in the product is the better
cost/benefit, and this spike remains a default-off, documented capability.

---

## 9. How to reproduce

```bash
cd sdk/rust-core

# Parity + static-extraction + measurement tests (parity MUST pass):
cargo test --features whitebox-spike whitebox::

# Release per-tag latency + table-size print:
cargo test --release --features whitebox-spike \
  whitebox::tests::perf_and_size_report_prints_numbers -- --nocapture

# Default build is byte-for-byte unchanged (feature off):
cargo build --release && sha256sum target/release/libkseal_ffi.so

# Raw key absent from the feature-on artifact:
cargo build --release --features whitebox-spike
grep -a -c "kseal-test-instance-key" target/release/libkseal_core.rlib   # -> 0
```
