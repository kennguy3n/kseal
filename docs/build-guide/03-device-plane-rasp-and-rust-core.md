# Chapter 3 — The device plane: RASP + a shared Rust trust core

> **The decision:** What runs on the phone, what language is it written in, and how do you
> keep protection *invisible* when the budget is sub-40 ms startup and single-digit-MB memory?

---

## The shape of the on-device SDK

The device plane has two layers:

- **A thin native surface per platform** — Kotlin/Java on Android (`sdk/android/`), Swift/ObjC
  on iOS (`sdk/ios/`) — that owns lifecycle integration, the public API the app developer
  calls, and the OS-specific probes and attestation hooks (Play Integrity / App Attest).
- **One shared Rust trust core** (`sdk/rust-core/kseal-core/`) that owns everything that must
  be *identical* across platforms: policy evaluation, risk normalization, the crypto message
  formats, compression, and deterministic serialization.

```
sdk/
├── android/   Kotlin/Java + NDK — probes, lifecycle, JNI → Rust
├── ios/       Swift/ObjC — probes, App Attest/DeviceCheck → Rust via C FFI
├── desktop/   macOS (SwiftPM) + Windows (.NET) on the same C FFI
└── rust-core/ the shared trust core (policy, crypto, events, transport)
```

### Why Rust for the core

The trust core is security-critical, performance-critical, and must produce **byte-identical**
outputs on every platform (a request proof computed on iOS must verify with the exact bytes
the Go server expects). Rust gives you:

- memory safety without a GC pause on the hot path,
- one implementation of the crypto/serialization contract instead of three drifting ones,
- a clean C ABI that Android (JNI), iOS (C FFI) **and** desktop (the same C FFI) all consume.

The risk signals live in one place — `sdk/rust-core/kseal-core/src/risk.rs` — as a stable
bitset (`ROOT`, `JAILBREAK`, `EMULATOR`, `DEBUGGER`, `HOOKING`, `TAMPER`, `APP_INTEGRITY`,
`NETWORK_MITM`, `PROXY`, `REPACKAGED`, …). Stable bit positions are a contract: the server,
the SIEM and the policy all reference them, so they're tested (`bit_positions_are_stable`).

---

## The probes (RASP), and why they only *gather*

The native probes detect the classic threats — root/jailbreak, emulator, debugger, hooking
frameworks, repackaging/integrity, network MITM/proxy. On Android they're under
`sdk/android/.../probes/` (`RootDetector`, `EmulatorDetector`, `DebuggerDetector`,
`HookDetector`, `IntegrityChecker`, `NetworkRiskDetector`); iOS mirrors them.

The critical design choice: **probes set risk bits; they do not decide.** A probe that finds
Frida sets the `HOOKING` bit and moves on. Whether that means ALLOW, STEP_UP or DENY is a
*server* decision against the active policy. This is the thesis from
[Chapter 1](01-thesis-and-business-case.md) made concrete: the client gathers evidence; the
server decides. A patched-out probe degrades a signal; it doesn't grant trust.

---

## Staying invisible: the 40 ms budget is a hard spec

Performance isn't a nice-to-have here; an SDK that adds jank gets removed. The hard budgets
(enforced by SDK perf tests in CI) are:

| Budget | Target |
|---|---|
| Startup overhead (p95) | **< 40 ms** |
| Resident memory | **< 3–5 MB** |
| Android AAR | **< 500 KB** | 
| iOS slice | **< 800 KB** |
| CPU (avg) | **< 0.5%** |
| Network at launch | **none** |

The Criterion benches in `sdk/rust-core/kseal-core/benches/core_benches.rs` measure the
hot-path operations directly. Measured on an x86-64 dev host (phones are slower, but these are
nanosecond/microsecond operations — orders of magnitude under any perceptible budget):

| Operation | Measured (median) |
|---|---|
| `core_new` (init the trust core) | **≈ 158 ns** |
| `policy_evaluate` (score bits → decision) | **≈ 48 ns** |
| `request_proof_generate` (HMAC) | **≈ 349 ns** |
| `config_verify_and_decode_ed25519` | **≈ 54 µs** |
| `batch_and_compress_10` (telemetry) | **≈ 35 µs** |

How those numbers stay small is the design:

- **No launch-time network call.** Initialization is local (~158 ns); the SDK never blocks
  startup on a round-trip. Telemetry is batched and deferred.
- **Risk-driven scheduling, not a heartbeat.** Checks run lazily and escalate with risk, so
  CPU scales with threat, not with a fixed timer.
- **The expensive primitive runs rarely.** Ed25519 config verification (~54 µs) only runs when
  a *new signed config* arrives — not per request. The per-request cost is a single HMAC.
- **Compact wire format.** Protobuf + zstd (optionally dictionary-trained) keeps telemetry
  batches tiny; the compression itself is microseconds.

---

## How the device talks to the server (preview)

The core produces two things the server cares about: **compressed signed telemetry** (events,
batched) and a **per-request proof** that binds an API call to the current trust state. The
proof construction is the cross-platform crypto contract and gets its own chapter
([Chapter 4](04-trust-protocol-attestation-and-proofs.md)) because getting its byte layout
*exactly* right across Rust-on-device and Go-on-server is the make-or-break detail.

One more on-device control worth calling out now: the **PrivacyGuard**
(`sdk/rust-core/kseal-core/src/events.rs`) drops disallowed fields **at the source**, before
anything is serialized or sent. Minimization isn't a server-side filter you hope holds — it's
enforced on the device (see [Chapter 7](07-privacy-and-compliance.md)).

---

## The business read

- **"Invisible" is a sales requirement, not just an engineering one.** The buyer's product
  team will veto anything that touches startup time or battery. The 40 ms budget and the
  no-launch-network rule are how you survive that review.
- **One Rust core = one third the maintenance and one consistent security surface.** You audit
  the crypto once, not per platform — and the same core powers the desktop SDKs for free.
- **Probes-gather-only is the durability story you sell.** You can tell a customer, honestly,
  that a cracked client degrades a signal but doesn't mint trust — because the decision was
  never on the device.

Next: [Chapter 4 — The trust protocol](04-trust-protocol-attestation-and-proofs.md), where the
device's evidence becomes an unforgeable, server-authoritative decision.
