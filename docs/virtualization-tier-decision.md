# Phase 5.3 — Code-Virtualization Tier: Decision Spike & GO/NO-GO

**Status:** Decision spike (prototype + analysis). Not a production rollout.
**Plan item:** 5.3 — *"(XL, optional) Virtualization tier. Only if product wants
to match DexGuard/iXGuard's top tier; biggest cost vs. crash-debuggability.
Recommend gating behind an explicit opt-in strength level with documented
tradeoffs. Decision gate: go/no-go after 5.1–5.2 telemetry."*
**Scope of this document:** the three deliverables of the spike — (A) a bounded,
feature-gated Rust prototype, (B) this design doc, and (C) the recommendation.

---

## 1. Recommendation: **NO-GO (defer)** — do not productionize a virtualization tier now

**Do not build or ship a code-virtualization tier to the fleet at this time.**
Keep the capability as a documented, default-off spike. Revisit *only* on an
explicit product/tenant requirement to match DexGuard/iXGuard's top tier (see
§9 for the conditions that would flip this to GO).

**Why, in one paragraph.** kseal's trust decision is **server-side**: the server
independently verifies platform attestation, the signed request proof, and the
reproducible `build_hash`, so a client that tampers with a local gate still does
not obtain a server-accepted trust decision. Selective virtualization would add
resistance to *static RE / automated devirtualization / patch-and-resign of one
routine* on top of the already-shipped 5.1 (bytecode CFG flattening + MBA), 5.2
(native string obfuscation), Phase 4 (RASP / anti-debug / anti-Frida /
self-integrity), and per-build polymorphism. The prototype shows the **runtime
costs are individually manageable** (size is single-digit KB; the perf tax only
matters for cold code, which is the whole point of doing it selectively). The
blocking factors are not raw size or speed — they are (1) the **engineering cost
of a maintained source→bytecode lowering** (the spike hand-lowers *one*
function; productionizing means owning a small compiler), (2) the **operational
cost of private crash-symbolication** (a retrace-map pipeline, key custody, and
Crashlytics/Play/Sentry integration), and (3) the **low marginal security
benefit** relative to that cost, given the server-side-trust thesis. Net: the
cost/benefit does not clear the bar today. The spike de-risks a *future* GO.

| | Verdict |
|---|---|
| **Recommendation** | **NO-GO (defer).** Default-off, documented, not shipped. |
| **One-line rationale** | Server-side trust + the existing 5.1/5.2/Phase-4 stack make virtualization's marginal benefit too small to justify the lowering-compiler and crash-symbolication burden. |
| **Cost driver** | Build-infra (source→VM lowering) + crash-symbolication ops, **not** binary size or cold-path latency. |
| **Flip to GO if** | A concrete contractual/DRM-grade requirement to match top-tier vendors appears (§9). |

This matches kseal's existing stated posture — `ARCHITECTURE.md` already lists
"Heavy virtualization / VM obfuscation" under *What to avoid* ("marginal benefit
when the real decision is server-side"), and `docs/build-hardening-android.md`
documents why the build-time hardening stops short of bytecode-VM obfuscation.
This spike confirms that judgment **with measurements** rather than by assertion.

---

## 2. What was built (deliverable A) — and what is CI-validated

A bounded, **feature-gated** (`vm-spike`, default **off**) Rust prototype lives
entirely in the trust core at `sdk/rust-core/kseal-core/src/vmspike/`. It is
additive and isolated: it does **not** touch the trust/crypto/kill-switch/proof
paths, adds **nothing** to the FFI C ABI, and with the feature off the standard
build is byte-for-byte unchanged (the only change to an existing source file is a
single `#[cfg(feature = "vm-spike")] pub mod vmspike;` line in `lib.rs`).

| Module | Role |
|---|---|
| `vmspike/isa.rs` | A 10-opcode **register VM** ISA; the representative routine `native_tag_mix` (a self-contained toy mixer — **not** real crypto) and its **hand-lowering** to bytecode, recording a retrace entry per instruction. |
| `vmspike/interp.rs` | The **dispatch loop** (safe Rust, no `unsafe`). Faults return a `VmError` carrying the faulting program counter (`VmFrame`) instead of panicking. |
| `vmspike/encode.rs` | **Per-build-polymorphic** byte encoding: opcode permutation + register permutation + XOR keystream, all derived deterministically from a 32-byte `BuildSeed` via SHA-256 (reusing the crate's existing `sha2` dep — zero new third-party code). |
| `vmspike/retrace.rs` | The **encrypted de-virtualization / retrace map** (VM pc → source site) and a `Symbolicator` that resolves a captured crash frame; opening with the wrong seed fails cleanly. |
| `vmspike/mod.rs` | Orchestration, the artifact bundle, and the measurement harness + tests. |

**What is CI-validated (the Rust prototype):** the `release-gate.yml` `build-test`
job runs `make build` / `make lint` / `make test`, and those targets were
extended so the spike is compiled, **clippy-clean** (`-D warnings`), and **tested
under `--features vm-spike`** on every run — in addition to the default and
`obfuscate-strings` builds. The release **artifacts** (`build-rust`) are
deliberately left unchanged: the spike is never linked into a shipped binary.

The behavioral properties proven by tests (`cargo test --features vm-spike`):

- **Byte-identical behavior** — `virtualized_is_byte_identical_to_native_over_random_inputs`
  runs 4,000 randomized `(input, domain)` cases asserting `vm == native`.
- **Per-build polymorphism + reproducibility** —
  `polymorphism_two_seeds_differ_yet_both_compute_correctly`: two seeds produce
  different bytecode, a fixed seed is deterministic (reproducible `build_hash`),
  and both decode + run correctly; `decoding_with_the_wrong_seed_fails` shows a
  devirtualizer for one build gets nothing from another's bytecode.
- **Crash-symbolication** — `captured_crash_frame_resolves_to_the_right_source_site`
  forces a real fault in the dispatch loop, resolves the captured pc through the
  **encrypted** map back to `native_tag_mix`, and confirms the wrong key cannot
  open the map.

**What is design-only (not in code):** a source→bytecode lowering for *arbitrary*
Rust (the spike hand-lowers one function), the production AEAD/KMS for the
retrace map (the spike uses an in-repo XOR keystream), and the crash-pipeline
integrations. These are scoped in §6 and §8.

---

## 3. Threat model

### 3.1 What selective virtualization defeats

- **Static reverse engineering of a specific routine.** The routine's real
  instructions are replaced by custom bytecode executed by a bundled
  interpreter; a disassembler sees only the dispatch loop, not the algorithm.
- **Automated, *transferable* devirtualization.** Because the virtual ISA,
  handler order, and keystream are **polymorphic per build** (deterministic from
  the build seed), a devirtualizer reconstructed for one build does not
  generalize to the next. The spike's `decoding_with_the_wrong_seed_fails`
  property is the concrete demonstration.
- **Patch-and-resign of the critical routine.** Locating and surgically editing
  the protected logic in a static binary is much harder when it is bytecode
  behind a per-build VM, raising the cost of a durable client-side bypass.

### 3.2 What it does **not** do (and is not for)

- **It is not confidentiality for secrets.** A shipped secret is still
  extractable at runtime; protecting key material is white-box crypto (Phase 6),
  not virtualization. kseal's model is explicitly *"no secret to steal"*.
- **It does not change the trust decision.** The server verifies attestation +
  signed proof + `build_hash` independently. Defeating a *client-side*
  virtualized gate does not yield a server-accepted trust token — so the
  marginal value of virtualization is bounded by what client-local resistance is
  worth, which in a server-authoritative design is modest.
- **It is not a hot-path technique.** The perf tax (§7) confines it to cold,
  low-frequency code.

---

## 4. What to virtualize in kseal (if it were ever GO)

**Cold + critical only.** Candidates (all low-frequency, security-relevant glue —
*not* the cryptographic primitives themselves):

- proof-signing **glue** (assembly/ordering around the signature, not the
  Ed25519/HMAC math),
- the **kill-switch verify gate** (the decision wrapper, not the verification
  primitive),
- **attestation-token assembly** (nonce/claims marshalling).

**Explicitly excluded:**

- **Hot paths** — risk scoring, event ingest/serialization, transport. The perf
  tax (§7) is disqualifying.
- **Golden-vector crypto primitives** — `verify_ed25519`, `hmac_sha256`,
  `sha256`, `generate_request_proof`, `kill_switch_preimage`. These must remain
  byte-identical to the cross-platform golden vectors and must stay
  symbolicatable; virtualizing them buys nothing (the secret isn't in them) and
  risks the contract.

The general rule mirrors the commercial consensus: mark a *handful* of cold
critical functions; never whole-program, never hot loops.

---

## 5. Layering and the polymorphic-per-build VM design

Virtualization is always the **top layer**, never a replacement:

```
        ┌──────────────────────────────────────────────┐
 5.3 →  │  selective code virtualization (cold gates)    │   ← this spike
        ├──────────────────────────────────────────────┤
 5.2 →  │  native string obfuscation (obfstr! XOR)       │
 5.1 →  │  bytecode CFG flattening + MBA (Gradle ASM)    │
 P4  →  │  RASP: anti-debug / anti-Frida / self-integrity│
        ├──────────────────────────────────────────────┤
        │  per-build HKDF polymorphism seed (all layers) │
        ├──────────────────────────────────────────────┤
        │  server-side attestation + signed proof + build_hash (authoritative) │
        └──────────────────────────────────────────────┘
```

**Polymorphic-per-build VM.** The spike derives, from an explicit 32-byte build
seed (in production: the existing per-build HKDF seed / `build_hash`):

- an **opcode permutation** — the wire byte for each opcode tag,
- a **register permutation** — the wire byte for each register index, and
- a **keystream** XORed over the whole encoded program.

Same source program + same seed ⇒ **identical** bytes (so `build_hash` stays
reproducible — no per-build nondeterminism). Different seed ⇒ completely
different bytecode. This is the property that prevents a single devirtualizer
from amortizing across builds, and it reuses kseal's existing per-build seed
discipline rather than inventing a new one.

---

## 6. Crash-symbolication: the crux, and the mitigation

**The cost.** Every virtualized method crashes *inside the VM dispatch loop*.
Standard `mapping.txt`/dSYM map the interpreter, not "VM program → source," so a
crash in a virtualized routine is opaque to ordinary symbolication. For a
platform serving thousands of tenants, losing triage on a security-critical gate
is a serious operational regression. This is the single biggest reason
build-time hardening here has historically stopped short of virtualization.

**The mitigation (prototyped).** Emit, at build time, a **private
de-virtualization / retrace map** — `VM pc → {function, step, source line}` — and
ship it **out of band**, encrypted, keyed off the `build_hash`. On a crash, the
captured VM frame (pc) is resolved internally through the map; attackers who lift
the artifact without the key get nothing. This mirrors Guardsquare's "retrace".

The spike implements this end-to-end (`vmspike/retrace.rs`): the map is
serialized with a magic header + checksum and XOR-encrypted under a
seed-derived key. `Symbolicator::open` with the right seed resolves a captured
frame to `native_tag_mix`; with the wrong seed it fails the magic/checksum check.

**Production integration (design-only).**

- Replace the in-repo XOR keystream with a real **AEAD (e.g. AES-256-GCM)** under
  a **KMS-managed key** — reuse the existing `TenantSealer`/CMK envelope seam
  (`KSC1`) already used for signing keys, keyed by `build_hash`.
- Upload the encrypted map as a **build artifact** at release time (alongside the
  `kseal.build-proof/v1` manifest registered via `RegistryService.CreateBuild`).
- Crash pipeline: ingest raw crashes from **Crashlytics / Play Console /
  Sentry** (which still symbolicate everything *outside* the virtualized core via
  the untouched `mapping.txt`/dSYM), then run a **server-side retrace step** that
  decrypts the map for the crash's `build_hash` and rewrites VM frames to source
  sites before they reach triage dashboards. The decryption key never leaves the
  control plane.

This is buildable, but it is **net-new operational surface** (artifact custody,
key rotation, a retrace microservice, dashboard wiring) that must be owned and
on-call'd — a real cost weighed in §1.

---

## 7. Perf & size budget (prototype's measured numbers)

> Measured with the in-repo harness `vmspike::measure` (see `vmspike/mod.rs`),
> `cargo test --release --features vm-spike perf_and_size_report -- --nocapture`,
> on this session's x86_64 Linux toolchain (`rustc` stable, release profile:
> `opt-level=3, lto=true, codegen-units=1`). Absolute ns are
> machine-dependent; the **ratios and byte counts** are the portable signal.
> Timing is printed, never asserted, so CI stays stable.

### 7.1 Throughput (native vs. virtualized)

| Input bytes | native ns/op | virtualized ns/op | perf tax |
|---:|---:|---:|---:|
| 0 | 0.77 | 14.57 | **18.8×** |
| 1 | 1.43 | 31.40 | **22.0×** |
| 8 | 10.71 | 151.69 | **14.2×** |
| 32 | 57.45 | 585.75 | **10.2×** |
| 256 | 636.43 | 4530.51 | **7.1×** |

The per-VM-instruction dispatch overhead is roughly constant (~2 ns/instr), so
the *ratio* shrinks as the native routine does more work per call. For a small
**cold gate** (the only valid target) the tax is **~10–22×**, but the
**absolute** cost is sub-microsecond — negligible for code that runs at most
once per attestation. This is exactly why the technique is "cold code only": on a
hot path the same 10–22× would be disqualifying.

### 7.2 Size (machine-code / artifact bytes)

| Item | Bytes | Notes |
|---|---:|---|
| `native_tag_mix` machine code | 192 | the routine being replaced (measured standalone, `opt-level=3`). |
| Encoded **bytecode** for the routine | 77 | per-function shipped cost (replaces the 192 B). |
| Interpreter dispatch core (`run_with_fuel`) | ~520 | **fixed**, shared by every virtualized function. |
| Load-time decoder + key schedule (`decode` + `decode_instr` + `BuildKey::derive` + `subkey`) | ~7,400 | **fixed**, shared; one-time. |
| Encrypted retrace map for the routine | 627 | private, out-of-band — **not** in the shipped binary. |

**Net size impact is negligible.** The shipped runtime footprint is a **fixed
~8 KB** (interpreter + load-time decoder + key schedule), amortized across *all*
virtualized functions, plus ~77 B of bytecode per function (which actually
*replaces* ~192 B of native code). Virtualizing a handful of cold gates costs on
the order of single-digit KB total — trivial against the SDK footprint budget
(< 3–5 MB). **Size is not the blocker; build-infra and ops are (§1, §8).**

---

## 8. Build-infra requirements

A production tier needs materially more than the spike:

1. **A source→bytecode lowering ("a small compiler").** The spike hand-lowers
   *one* function. Real use needs a maintained, tested lowering for the marked
   functions, kept correct as the ISA evolves per build. This is the dominant
   engineering cost and an ongoing maintenance liability.
2. **A polymorphic ISA generator** wired to the existing per-build HKDF seed, so
   the VM differs per build while `build_hash` stays reproducible. (The spike's
   `encode.rs` is the model; it already keys off an explicit seed.)
3. **The encrypted retrace-map pipeline** (§6): AEAD-under-KMS, artifact upload,
   and the server-side retrace microservice + Crashlytics/Play/Sentry wiring.
4. **CI/toolchain.** The selective, in-language spike builds and tests on CI's
   stock `dtolnay/rust-toolchain@stable` (this PR proves it). A
   **whole-program, OLLVM-style** virtualization pass would **not**: it requires
   a custom LLVM/obfuscator toolchain that stock `rust-toolchain@stable` cannot
   provide — the **same constraint that deferred the 5.2 whole-program LLVM CFG
   tier**. If virtualization is ever pursued, the **selective, source-lowered**
   approach prototyped here is the only one compatible with the current CI, and
   is also the commercially-recommended one (region-based, never whole-program).

---

## 9. GO/NO-GO rationale and revisit conditions

**Decision: NO-GO (defer).** The measured evidence shows the *runtime* costs are
small, but the **engineering + operational costs are real and the marginal
security benefit is low** because trust is server-authoritative and four
hardening layers already raise the client-tamper cost. Spending an XL effort plus
permanent maintenance and on-call surface to harden a *client-local* gate that
the server does not rely on is not justified now. The conservative, safe default
is to **not** ship it, keep the spike default-off, and preserve full
symbolication on the shipped build.

**Flip to GO only if all of these hold:**

1. A concrete product/tenant requirement to **match DexGuard/iXGuard's top
   tier** appears (e.g. DRM-grade media, a contractual "virtualization" checkbox,
   or a regulator/customer audit demanding it).
2. 5.1–5.2 **telemetry** shows client-side static-RE / patch-and-resign attacks
   are actually material *and* not already deterred by the existing stack.
3. There is committed ownership for the **source→bytecode lowering** and the
   **retrace-map pipeline** (build + on-call), with the AEAD/KMS retrace
   integration landed *before* any virtualized routine ships.

If GO: ship behind an **explicit opt-in strength level**, scoped to the cold
critical gates in §4, with the §4 exclusions enforced, the §6 mitigation live,
and the §5 reproducibility (deterministic-from-seed) preserved.

---

## 10. Appendix — reproduce the measurements

```bash
cd sdk/rust-core
# Build, lint, and test the spike (all default-off elsewhere):
cargo build --features vm-spike
cargo clippy --all-targets --features vm-spike -- -D warnings
cargo test  --features vm-spike

# Print the perf/size sweep used in §7:
cargo test --release --features vm-spike perf_and_size_report -- --nocapture
```

Machine-code sizes in §7.2 were read with
`nm --print-size --demangle` on the release `libkseal_core` rlib (interpreter /
decoder symbols) and on a standalone `opt-level=3` compile of the routine
(`native_tag_mix`, which is otherwise inlined away).
