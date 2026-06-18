# Code-Virtualization Tier: Decision (5.3) → Production Increment (5.4) — **GO**

**Status:** GO. The 5.3 decision spike's NO-GO was **overridden by the product
owner**; this tier is now being productionized **selectively and opt-in, gated
behind the highest obfuscation strength (`HIGH`)**. This document records the GO
decision, the first CI-validated production increment (5.4), and the
productionization roadmap for the remaining XL work.
**Plan item:** 5.3 — *"(XL, optional) Virtualization tier… Recommend gating
behind an explicit opt-in strength level with documented tradeoffs. Decision
gate: go/no-go after 5.1–5.2 telemetry."*
**Scope of this document:** the GO recommendation (§1), what the 5.3 spike and
the 5.4 increment built and CI-validate (§2), threat model (§3), what to
virtualize (§4), the polymorphic VM + the new IR→bytecode compiler (§5), the
encrypted+authenticated retrace map (§6), measured perf/size for both the spike
and this increment (§7), and the **productionization roadmap** (§8) plus the
per-build go/no-go gates (§9).

---

## 1. Recommendation: **GO (productionize, selectively, opt-in behind `HIGH`)**

**Ship a selective code-virtualization tier, off by default and engaged only at
`ObfuscationStrength.HIGH`.** Virtualize a *handful* of cold, security-relevant,
non-crypto routines via a maintained source→bytecode compiler with per-build
polymorphism; keep full crash-triage through a private, encrypted+authenticated
retrace map; and **never** virtualize any routine that feeds a golden vector or
sits on a hot path. This tier is a **top layer that raises the bar against
static RE, automated/transferable devirtualization, and patch-and-resign of a
single routine** — it is explicitly *not* a replacement for kseal's
server-authoritative trust decision, and it protects no secret.

**Why GO now, in one paragraph.** The 5.3 spike's blocking concern was never raw
size or speed — it was the engineering cost of *owning a small compiler* and the
operational cost of *private crash-symbolication*. This 5.4 increment retires the
first risk and de-risks the second **with shipping, CI-validated code**: the
hand-lowered one-function spike is replaced by a real, maintained **IR→bytecode
lowering** (a Sethi–Ullman register allocator over a 12-operation integer/bitwise
IR) proven byte-identical to native evaluation across **>24,000 randomized
expression/input pairs**, and the retrace map is upgraded from an XOR+checksum
toy to a **SHA-256-CTR–encrypted, HMAC-SHA256–authenticated, `build_hash`-bound**
artifact with round-trip, wrong-key, tamper, and build-binding tests. The tier is
wired end-to-end behind `HIGH` against one representative cold routine, and the
measured costs remain small (single-digit-KB fixed footprint; a cold-only perf
tax whose *absolute* cost is sub-microsecond). Given a concrete product mandate to
match DexGuard/iXGuard's top tier, the cost/benefit now clears the bar — provided
the rollout stays selective, opt-in, golden-safe, and bounded by the roadmap in
§8.

| | Verdict |
|---|---|
| **Recommendation** | **GO.** Productionize selectively, **default-off**, engaged only at `ObfuscationStrength.HIGH`. |
| **One-line rationale** | The compiler-ownership and crash-symbolication risks that drove the spike's NO-GO are now retired/de-risked in code; remaining work is bounded and roadmapped (§8). |
| **Scope guardrails** | Cold + non-crypto + golden-safe only (§4). Never hot paths, never golden-vector crypto, never whole-program. |
| **Honesty clause** | A top hardening layer over server-side trust + the 5.1/5.2/Phase-4 stack — raises client-tamper cost, never the authority of the decision. |

This refines (does not contradict) kseal's stated posture: `ARCHITECTURE.md`
lists "heavy virtualization / whole-program VM obfuscation" under *what to avoid*.
The GO here is the **narrow, selective, region-based** variant the commercial
consensus actually recommends — not whole-program virtualization — kept opt-in so
the default fleet build is byte-for-byte unchanged.

---

## 2. What was built — spike (5.3) + this increment (5.4)

Everything lives in the trust core under `sdk/rust-core/kseal-core/src/vmspike/`,
behind the existing **`vm-spike`** cargo feature (default **off**). It is
additive and isolated: it does **not** touch the trust/crypto/kill-switch/proof
paths, adds **nothing** to the FFI C ABI, and with the feature off the standard
build is **byte-for-byte unchanged** (verified: the default release
`libkseal_core` rlib hash is identical to current `main`). The only edit to an
existing non-vmspike file remains the single `#[cfg(feature = "vm-spike")] pub
mod vmspike;` line in `lib.rs` already present from 5.3.

| Module | 5.3 spike | 5.4 increment (this PR) |
|---|---|---|
| `vmspike/isa.rs` | 10-opcode register ISA; hand-lowered `native_tag_mix`. | Extended to **18 opcodes / 16 registers** (adds `Sub/Mul/And/Or/Shl/Shr/Rotr/LoadInput`); `Builder` generalized so any lowering can emit + record retrace sites. Still safe Rust, no `unsafe`. |
| `vmspike/ir.rs` *(new)* | — | The **maintained compiler**: an `Expr` IR (const/input + add/sub/mul/xor/and/or/shl/shr/rotl/rotr), a native `eval` reference, **Sethi–Ullman `register_need`** analysis, and an automatic `lower()` from IR → bytecode. Rejects over-wide expressions and out-of-range inputs *before* codegen. |
| `vmspike/strength.rs` *(new)* | — | Rust mirror of the Gradle `ObfuscationStrength` (OFF/LOW/MEDIUM/HIGH, default OFF); `cohort_bucket()` runs the **native** routine at OFF/LOW/MEDIUM and the **virtualized** program at **HIGH** — behaviour-identical either way. |
| `vmspike/encode.rs` | Per-build-polymorphic encoder (opcode perm + register perm + XOR keystream from a 32-byte `BuildSeed` via the crate's existing `sha2`). | Extended to encode the new opcodes; legacy path unchanged. |
| `vmspike/interp.rs` | Byte-input dispatch loop; faults return a `VmFrame` (pc) instead of panicking. | Adds a word-oriented `run_ir` entry point for IR programs + dispatch for the new opcodes. Shared core; legacy byte path unchanged. |
| `vmspike/retrace.rs` | XOR-keystream + FNV-checksum "encrypted" map + `Symbolicator`. | Upgraded to **SHA-256-CTR encryption + HMAC-SHA256 authentication (encrypt-then-MAC) + `build_hash` binding**, using the crate's existing vetted `hmac`/`sha2` deps. Constant-time verify. |
| `vmspike/mod.rs` | Orchestration, artifact bundle, measurement harness, tests. | Adds the IR-cohort measurement (`measure::run_cohort`) and updates call sites for the authenticated retrace API. |

**CI-validated (no new heavy deps; `Cargo.lock` not churned).** The
`release-gate.yml` `build-test` job runs `make build` / `make lint` / `make test`,
which compile and test the spike under `--features vm-spike`, clippy-clean
(`-D warnings`), on every run. The shipped release **artifacts** remain unchanged
— the tier is never linked into a default build.

**Behavioral properties proven by tests** (`cargo test --features vm-spike`):

- **Compiler correctness (the backbone)** —
  `ir::…::lowered_vm_is_byte_identical_to_native_eval_over_thousands_of_cases`
  generates 3,000 random IR expressions (depth ≤ 7, 1–4 inputs) and runs each
  over 8 random input vectors — **>24,000** `(expr, input)` pairs — asserting the
  decoded, per-build-encoded VM result equals the native `eval`. The original
  `virtualized_is_byte_identical_to_native_over_random_inputs` (4,000 cases for
  the hand-lowered routine) is retained.
- **IR per-build polymorphism + reproducibility** —
  `lowering_is_deterministic_but_encoding_is_per_build_polymorphic`: identical IR
  lowers to an identical program (reproducible `build_hash` input), two seeds
  produce **different** bytecode, each seed is deterministic, the correct seed
  decodes/runs and the **wrong seed fails to decode**.
- **Compiler safety rails** — `rejects_expression_that_overflows_the_register_bank`
  and `rejects_input_slot_out_of_range` prove the allocator's bound is enforced
  before lowering.
- **End-to-end HIGH gating** — `strength::…::every_strength_yields_the_native_result`
  and `high_strength_actually_runs_the_vm_path`: OFF/LOW/MEDIUM/HIGH all return
  the same value, and HIGH demonstrably executes the VM path.
- **Crash-symbolication + map confidentiality/integrity** —
  `captured_crash_frame_resolves_to_the_right_source_site` forces a real
  dispatch-loop fault and resolves the captured pc through the **encrypted**
  map back to source; `wrong_seed_cannot_open_the_map` (auth fails — useless
  without the key), `tampering_any_byte_is_detected` (HMAC catches ciphertext and
  tag edits), `map_is_bound_to_its_build_hash` (a map cannot be paired with
  another build), and `entries_are_encrypted_not_plaintext` (source identifiers
  never appear in the clear).

**Still design-only (scoped in §8):** a lowering for *arbitrary* Rust beyond the
integer/bitwise IR; the **KMS/HSM-managed** key for the retrace map (the
increment uses a `BuildSeed`-derived in-process key); and the build-plugin +
crash-pipeline integrations.

---

## 3. Threat model

### 3.1 What selective virtualization defeats

- **Static reverse engineering of a specific routine.** The routine's real
  instructions are replaced by custom bytecode run by a bundled interpreter; a
  disassembler sees only the dispatch loop, not the algorithm.
- **Automated, *transferable* devirtualization.** The virtual ISA, handler order,
  and keystream are **polymorphic per build** (deterministic from the build
  seed), so a devirtualizer reconstructed for one build does not generalize to
  the next — concretely demonstrated by the wrong-seed-fails-to-decode property
  on the IR path.
- **Patch-and-resign of the critical routine.** Locating and surgically editing
  the protected logic in a static binary is far harder when it is bytecode behind
  a per-build VM, raising the cost of a durable client-side bypass.

### 3.2 What it does **not** do (and is not for)

- **It is not confidentiality for secrets.** A shipped secret is still
  extractable at runtime; protecting key material is white-box crypto (Phase 6),
  not virtualization. kseal's model is explicitly *"no secret to steal."*
- **It does not change the trust decision.** The server verifies attestation +
  signed proof + `build_hash` independently; defeating a *client-side*
  virtualized gate yields no server-accepted trust token. The marginal value is
  bounded by what client-local resistance is worth in a server-authoritative
  design.
- **It is not a hot-path technique.** The perf tax (§7) confines it to cold,
  low-frequency code.

---

## 4. What to virtualize in kseal

**Cold + critical + non-crypto only.** Production candidates (all low-frequency,
security-relevant glue — *not* the cryptographic primitives themselves):

- proof-signing **glue** (assembly/ordering around the signature, not the
  Ed25519/HMAC math),
- the **kill-switch verify gate** (the decision wrapper, not the verification
  primitive),
- **attestation-token assembly** (nonce/claims marshalling).

**This increment virtualizes a deliberately safe stand-in for those:**
`ir::demo_cohort_native` — an opaque device-cohort bucketing function over
`(device_hi, device_lo, salt)` using only mixing arithmetic. It is **cold,
non-crypto, and feeds no golden vector**, so virtualizing it cannot perturb any
pinned output. It exists to prove the lowering is wired through `strength`
selection, not to protect anything. Extending to the real candidates above is
roadmapped in §8.3 **with the parity-test strategy that keeps golden vectors
byte-identical**.

**Explicitly excluded (hard constraint, CI-enforced):**

- **Hot paths** — risk scoring, event ingest/serialization, transport. The perf
  tax (§7) is disqualifying.
- **Golden-vector crypto primitives** — `verify_ed25519`, `hmac_sha256`,
  `sha256`, `generate_request_proof`, `kill_switch_preimage`, the signed-config
  signature. These must remain byte-identical to the cross-platform golden
  vectors **in both the default and feature-on builds** and must stay
  symbolicatable; virtualizing them buys nothing (the secret isn't in them) and
  risks the contract. (Verified: the crypto golden-vector tests pass identically
  with and without `--features vm-spike`.)

The rule mirrors the commercial consensus: mark a *handful* of cold critical
functions; never whole-program, never hot loops.

---

## 5. Layering, polymorphic VM, and the IR→bytecode compiler

Virtualization is always the **top layer**, never a replacement:

```
        ┌──────────────────────────────────────────────┐
 5.3/5.4 │ selective code virtualization (cold gates)    │   ← this tier, opt-in @ HIGH
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

### 5.1 The maintained compiler (`ir.rs`) — the core of this increment

The spike hand-lowered exactly one function. That is replaced by an automatic,
testable lowering:

1. **IR.** `Expr` is a tree of pure 64-bit integer/bitwise ops: `Const`, `Input`,
   `Add/Sub/Mul`, `Xor/And/Or`, `Shl/Shr` and `Rotl/Rotr` (shift/rotate amounts
   masked to `&63`). `eval()` is the straightforward native reference the
   property tests compare against.
2. **Register-need analysis (Sethi–Ullman).** `register_need()` computes the
   exact register count the code generator will consume: a leaf needs 1; a
   shift/rotate reuses its operand's registers; a commutative binary node needs
   `max(hi, lo+1)` (heavier child first), and the non-commutative `Sub` needs
   `max(need(a), need(b)+1)`. Because the generator's choices are *exactly* this
   model, `register_need(expr) ≤ NUM_REGS` is a sufficient-and-necessary fit
   condition — so oversized expressions are **rejected before** any bytecode is
   emitted (`LowerError::TooManyRegisters`), as are out-of-range input slots.
3. **Lowering.** `lower()` walks the tree, emits the new ISA ops into the
   generalized `Builder`, records a retrace site per node, and appends the
   `Ret`. The result is deterministic: **same IR ⇒ identical decoded program**,
   so `build_hash` stays reproducible.

This is a small, owned compiler with a real allocator and real rejection paths —
not a hand table — which is precisely the artifact the spike said productionizing
would require.

### 5.2 Polymorphic-per-build VM (unchanged seam, now driven by the compiler)

From an explicit 32-byte build seed (in production: the existing per-build HKDF
seed / `build_hash`), `encode.rs` derives an **opcode permutation**, a **register
permutation**, and a **keystream** XORed over the encoded program. Same program +
same seed ⇒ identical bytes (reproducible `build_hash`); different seed ⇒
different bytecode and a decoder for one build gets nothing from another's. The
5.4 IR path rides this same seam — the polymorphism tests now run against
compiler output, not a hand table.

---

## 6. Crash-symbolication: the crux, now a real encrypted+authenticated artifact

**The cost.** Every virtualized method crashes *inside the VM dispatch loop*.
`mapping.txt`/dSYM map the interpreter, not "VM program → source," so a crash in a
virtualized routine is opaque to ordinary symbolication. Losing triage on a
security-critical gate is a serious operational regression — historically the
single biggest reason build-time hardening stopped short of virtualization.

**The mitigation (now productionized in `retrace.rs`).** At build time we emit a
private map `VM pc → {function, step, source line}` and ship it **out of band**.
The 5.4 format is a proper AEAD-shaped construction:

- **Encryption.** The entry table is XORed with a **SHA-256 counter-mode
  keystream** under a seed+`build_hash`-derived key (`derive_key(seed,
  build_hash, "…enc")`). Source identifiers never appear in the clear (proven by
  `entries_are_encrypted_not_plaintext`).
- **Authentication.** The whole artifact (authenticated header ‖ ciphertext) is
  covered by an **HMAC-SHA256 tag** under a *separate* derived key
  (`"…mac"`), verified in **constant time** via the vetted `hmac` crate
  (`encrypt-then-MAC`). Any tampering or a wrong seed fails the tag
  (`AuthFailed`).
- **Build binding.** The `build_hash` is carried in the authenticated header and
  folded into both key derivations, so a map can only be opened against the build
  it was emitted for (`BuildHashMismatch`); it cannot be paired with another
  build's frames.

`Symbolicator::open(encrypted, seed, build_hash)` verifies, decrypts, and
resolves a captured `VmFrame`; without the key the artifact is indistinguishable
from random and unforgeable. This mirrors Guardsquare's "retrace" workflow.

**What remains design-only:** swapping the in-process `BuildSeed`-derived key for
a **KMS/HSM-managed** key and wiring the upload + server-side retrace step (§8.2).
The cryptographic shape (encrypt-then-MAC, AAD-bound, constant-time verify) is
already production-correct; only key custody and transport are outstanding.

---

## 7. Perf & size budget (measured)

> Measured with the in-repo harness `vmspike::measure` via
> `cargo test --release --features vm-spike perf_and_size_report -- --nocapture`,
> release profile (`opt-level=3, lto=true, codegen-units=1`). Absolute ns are
> machine-dependent and vary run-to-run; the **ratios and byte counts** are the
> portable signal. Timing is printed, never asserted, so CI stays stable.

### 7.1 Throughput — 5.3 hand-lowered routine (`native_tag_mix`)

| Input bytes | native ns/op | virtualized ns/op | perf tax |
|---:|---:|---:|---:|
| 0 | 0.77 | 14.57 | **18.8×** |
| 1 | 1.43 | 31.40 | **22.0×** |
| 8 | 10.71 | 151.69 | **14.2×** |
| 32 | 57.45 | 585.75 | **10.2×** |
| 256 | 636.43 | 4530.51 | **7.1×** |

Per-VM-instruction dispatch overhead is roughly constant, so the *ratio* shrinks
as the native routine does more work per call. For a small **cold gate** the tax
is ~10–22× but the **absolute** cost is sub-microsecond.

### 7.2 Throughput + size — 5.4 IR-compiled routine (`demo_cohort`)

The maintained-compiler path, measured end-to-end (lower → encode → decode → run)
by `measure::run_cohort`:

| Metric | Value | Notes |
|---|---:|---|
| Native | ~1.3 ns/op | 3-input pure mixer, no payload loop. |
| Virtualized | ~65 ns/op | cold-only; called at most once per attestation. |
| Perf tax | **~50×** | high *ratio*, negligible *absolute* (sub-µs). |
| Emitted instructions | **41** | produced by the compiler from the `Expr` tree. |
| Encoded **bytecode** | **162 B** | per-function shipped cost. |
| Encrypted retrace map | **1,303 B** | private, out-of-band — **not** in the shipped binary. |

The IR routine's tax is higher than the hand-lowered one (more VM instructions
per call, no amortizing payload loop), but it is still a **cold** routine whose
absolute per-call cost is ~65 ns — i.e. budget-irrelevant for code that runs once
per attestation. This is exactly why the tier is "cold code only."

### 7.3 Fixed footprint (shared across all virtualized functions)

| Item | Bytes | Notes |
|---|---:|---|
| Interpreter dispatch core | ~520 | **fixed**, shared by every virtualized function. |
| Load-time decoder + key schedule | ~7,400 | **fixed**, shared; one-time. |
| Per-function bytecode | 77–162 | replaces native machine code of similar size. |
| Per-function retrace map | 675–1,303 | private, out-of-band; not shipped in the binary. |

**Net size impact is negligible.** The shipped runtime footprint is a fixed
~8 KB (interpreter + decoder + key schedule), amortized across *all* virtualized
functions, plus ~77–162 B of bytecode per function. Virtualizing a handful of
cold gates costs single-digit KB total — trivial against the SDK footprint
budget. **Size is not the blocker; the roadmap items in §8 are the remaining
work.**

---

## 8. Productionization roadmap (remaining XL work)

This increment lands the compiler core and the authenticated retrace artifact.
The following are required before any *real* critical routine ships virtualized.

### 8.1 Own and maintain the source→bytecode lowering compiler

- **Testing strategy.** Keep the property-test backbone (random IR × random
  inputs, native-vs-VM byte-identity) as the gate for every ISA or codegen
  change; require it to grow with the IR. Add differential tests against a second
  independent evaluator, and fuzz the decoder against malformed bytecode. Pin the
  demo-cohort lowering with exact known-answer vectors.
- **ISA evolution.** Treat opcode additions as semver-like changes: extend
  `NUM_OPS`, the encoder permutation table, the interpreter dispatch, and the
  `register_need` model **together**, guarded by the polymorphism + property
  tests. Never let `register_need` and the generator drift — their equality is
  the allocator's correctness invariant.
- **Polymorphism.** Keep lowering deterministic (same IR ⇒ same program) so
  `build_hash` stays reproducible; all per-build variation must come from the
  seed-driven encoder, never from the compiler.

### 8.2 The private crash-symbolication pipeline

- **Build-plugin emission.** Emit the encrypted retrace map from the Gradle and
  Xcode build plugins as a release artifact, alongside the existing
  `kseal.build-proof/v1` manifest, keyed by `build_hash`.
- **Key custody.** Replace the in-process `BuildSeed`-derived key with a
  **KMS/HSM-managed** key (reuse the `TenantSealer`/CMK envelope seam already used
  for signing keys). The decryption key must never leave the control plane; the
  map ships encrypted and is only ever decrypted server-side. Rotate per build;
  bind to `build_hash`.
- **Crash-pipeline integration.** Ingest raw crashes from **Crashlytics / Play
  Console / Sentry / Apple symbolication** (which still symbolicate everything
  *outside* the virtualized core via the untouched `mapping.txt`/dSYM), then run a
  **server-side retrace microservice** that decrypts the map for the crash's
  `build_hash` and rewrites VM frames to source sites before triage dashboards.
- **Custody requirements (summary).** Encryption + authentication are already
  implemented (§6); production must add: KMS key lifecycle (rotation,
  revocation), least-privilege access to the retrace service, audit logging of
  every decrypt, and artifact retention tied to build retention.

### 8.3 Extend selective virtualization to the real critical paths

Targets: proof-signing **glue**, the kill-switch **verify gate**, and
attestation-token **assembly** (§4). The **parity-test strategy that keeps golden
vectors byte-identical**:

1. Express only the *non-crypto glue* as IR (never the Ed25519/HMAC/SHA
   primitives — those stay native and symbolicatable).
2. For every candidate, add a parity test asserting the virtualized routine's
   output equals the native one over randomized inputs **and** that the relevant
   golden vectors (proof HMAC tag, signed-config signature, kill-switch preimage)
   are **byte-identical in both the default and feature-on builds** — the same
   invariant this increment already enforces for the crypto suite.
3. CI gate: fail the build if any golden vector differs between default and
   `vm-spike` builds, or if the default rlib hash changes.

### 8.4 Build-plugin polymorphism, perf budget, rollout & per-build gates

- **Per-build polymorphism in the plugins.** Wire the encoder seed to the
  existing per-build HKDF seed in the Gradle/Xcode plugins, and surface
  virtualization as an explicit step at `ObfuscationStrength.HIGH` only (the Rust
  `strength.rs` mirror defines the contract; the Kotlin enum's `HIGH` arm is the
  integration point).
- **Perf budget.** Enforce cold/critical-only selection; add a build-time check
  that rejects virtualizing any function tagged hot or on the request path.
- **Rollout + telemetry + go/no-go-per-build gates.** Stage behind `HIGH` opt-in;
  collect crash-retrace success rate and per-build VM-fault telemetry; gate each
  build on (a) golden vectors unchanged, (b) default build unchanged, (c) retrace
  map decrypts and round-trips for a sampled fault, (d) perf within budget. Any
  gate red ⇒ no-go for that build (fall back to native).

---

## 9. GO rationale and per-build go/no-go gates

**Decision: GO**, under a product mandate to match top-tier vendors, because the
two costs that drove the spike's NO-GO are now addressed in code: the
**maintained compiler** exists with a real allocator, rejection paths, and a
>24,000-case correctness backbone; and the **crash-symbolication** artifact is a
real encrypted+authenticated, build-bound map with round-trip/wrong-key/tamper
tests. The runtime costs remain small and cold-only, and the default fleet build
is provably unchanged. The remaining work (§8) is bounded, roadmapped, and gated.

**Ship discipline (non-negotiable):**

1. **Opt-in only.** Default OFF; virtualization engages strictly at
   `ObfuscationStrength.HIGH`.
2. **Golden-safe.** Golden vectors byte-identical in default **and** feature-on
   builds; default build byte-for-byte unchanged. CI enforces both.
3. **Scope.** Cold + non-crypto only (§4 exclusions enforced). Never
   whole-program; never hot paths; no `unsafe`.
4. **Symbolication first.** No virtualized routine ships before the KMS-backed
   retrace pipeline (§8.2) is live for its build.
5. **Per-build gates.** Each build must pass §8.4's go/no-go gates or fall back to
   native.

Framed honestly: this tier raises the cost of static RE / automated
devirtualization / patch-and-resign of a single routine. It is a **top layer over
kseal's server-authoritative trust** and the already-shipped 5.1/5.2/Phase-4
stack — it strengthens client-tamper resistance, and it never becomes the thing
the trust decision depends on.

---

## 10. Appendix — reproduce the measurements

```bash
cd sdk/rust-core
# Build, lint, and test the tier (all default-off elsewhere):
cargo build --features vm-spike
cargo clippy --all-targets --features vm-spike -- -D warnings
cargo test  --features vm-spike

# Confirm the default (feature-off) build is byte-for-byte unchanged:
cargo build --release            # hash target/release/libkseal_core.rlib

# Print the perf/size sweep used in §7 (hand-lowered sweep + IR cohort line):
cargo test --release --features vm-spike perf_and_size_report -- --nocapture
```

Machine-code/fixed-footprint sizes in §7.3 were read with
`nm --print-size --demangle` on the release `libkseal_core` rlib (interpreter /
decoder symbols); the §7.1 sweep is the 5.3 spike's recorded numbers and the
§7.2 cohort figures are from this increment's `measure::run_cohort`.
