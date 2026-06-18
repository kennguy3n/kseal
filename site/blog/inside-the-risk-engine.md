# Inside the risk engine: 21 wire bits, 17 server signals

kseal turns a phone's self-observations into a single trust decision through a
small, fixed pipeline. There is no machine-learning black box here — the whole
thing is a bit translation, a union, a weighted sum, and a threshold lookup. That
is deliberate: every decision is explainable, reproducible, and pinned by tests
on both sides of the wire. This post is the guided tour, grounded in
**Meridian Pay** (`meridian` / `pay-android`, `STEP_UP`).

The full authoritative tables live in the
[risk-signals reference](https://github.com/kennguy3n/kseal/blob/main/docs/reference/risk-signals.md);
this post explains the *why* behind them.

## The pipeline

```
device signals (wire bits)
        │  FromWire — translate to the server layout
        ▼
server bits ──► Fuse (union with attestation-derived bits)
        │
        ▼
      Score (weighted, saturating add)
        │
        ▼
      Level (score → trust level via thresholds)
        │
        ▼
   Decision (level + enforcement mode → allow / step-up / deny)
```

## Stage 1 — two bit layouts, one mandatory translation

The single most important subtlety: **the device and the server do not share a
bit layout.** The device packs what it sees into 21 *wire* positions (bits
0–20). The server scores against a different 17-signal layout. The same number
means different things on each side — wire bit 4 is `wireDebugger`, but server
bit 4 is `BitAppTamper`.

A device bitset is therefore **never scored raw**. It first passes through
`FromWire`, which remaps each wire bit to the server bit it *means* and drops
wire bits that have no server meaning. Several wire bits intentionally collapse
onto one server signal — `wireRoot` (0) and `wireJailbreak` (1) both become
`BitRootJailbreak`; `wireTamper` (6), `wireAppIntegrity` (7) and `wireRepackaged`
(15) all become `BitAppTamper` — because the server cares about the *category of
risk*, not the platform-specific way it was observed.

Why bother with two layouts at all? Because they evolve independently. New
device probes can claim new wire positions without renumbering the server
scoring layout, and the layout is **append-only** — positions are never reused,
only added. The contract is pinned from both directions by
`TestWireToServerContract` (Go) and `TestRiskBitLayoutContract` (Rust), so the
device and server can never silently drift.

## Stage 2 — fuse in what the device can't report

Once device bits are in the server layout, `Fuse` unions them with signals the
device cannot produce itself:

```
fused = FromWire(device_bits) | attestation_bits
```

This is where `BitAttestationFail` (platform attestation verdict),
`BitAppUnrecognized` (the build isn't a registered `build_hash`), and
`BitFleetAnomaly` (a population-level surge, server bit **32**, far above the
device range) enter. `BitFleetAnomaly` sits at position 32 precisely so it can
never collide with anything a device might set. Fusion is a pure union: if any
source asserts a risk, it stays set.

## Stage 3 — score with a saturating weighted sum

Each server signal carries a default weight (a tenant policy can override any of
them). Scoring sums the weights of every set bit:

| Signal | Weight | | Signal | Weight |
|---|---|---|---|---|
| `app_unrecognized` | 65 | | `app_tamper` | 60 |
| `attestation_fail` | 70 | | `fleet_anomaly` | 50 |
| `device_integrity` | 45 | | `remote_access` | 45 |
| `root_jailbreak` | 40 | | `accessibility_abuse` | 40 |
| `hooking` | 35 | | `overlay_abuse` | 35 |
| `network_mitm` | 30 | | `screen_capture` | 30 |
| `debugger` | 25 | | `malicious_ime` | 25 |
| `emulator` | 20 | | `account_risk` | 20 |
| `environment_risk` | 15 | | | |

The weights encode a worldview: **a forged identity is worse than a hostile
environment.** Attestation failure (70) and an unrecognized build (65) dominate,
because they go to whether this is genuinely your app at all. A rooted phone
(40) or an emulator (20) is suspicious but not, by itself, disqualifying — plenty
of legitimate power users run rooted devices.

Addition **saturates** at the 32-bit maximum (`u32::saturating_add` in the Rust
core, mirrored in Go) so a hostile or fat-fingered policy can never overflow the
score and wrap it down to a deceptively low number.

## Stage 4 & 5 — level, then decision

The score maps to a trust level by fixed thresholds, and the level plus the
tenant's enforcement mode produces the decision:

| Level | Min score | `OBSERVE` | `STEP_UP` | `BLOCK` |
|---|---|---|---|---|
| `CRITICAL` | ≥ 130 | allow | **deny** | **deny** |
| `HIGH_RISK` | ≥ 90 | allow | **step-up** | **deny** |
| `MEDIUM_RISK` | ≥ 50 | allow | **step-up** | **step-up** |
| `LOW_RISK` | ≥ 20 | allow | allow | allow |
| `TRUSTED` | < 20 | allow | allow | allow |

`OBSERVE` never denies — it only records — which is how a tenant rolls kseal out
safely before enforcing. As risk rises, the server also tells the SDK which
probes to run before its next refresh via `NextChecks`, so a suspicious session
is scrutinized harder on its next pass.

## The five Meridian scenarios, by the numbers

Every figure below is computed by the real server logic and committed in
[`scenarios.json`](https://github.com/kennguy3n/kseal/blob/main/docs/reference/fixtures/scenarios.json):

| ID | Situation | Server signals | Score | Level | Decision (`STEP_UP`) |
|---|---|---|---|---|---|
| **D1** | Genuine install | — | 0 | `TRUSTED` | allow |
| **D2** | Rooted, otherwise genuine | `root_jailbreak` | 40 | `LOW_RISK` | allow |
| **D3** | Repackaged build, attestation fails | `app_tamper` + `attestation_fail` | 130 | `CRITICAL` | **deny** |
| **D4** | Overlay + accessibility tapjacking | `overlay_abuse` + `accessibility_abuse` | 75 | `MEDIUM_RISK` | step-up |
| **D5** | Remote-access scam | `screen_capture` + `accessibility_abuse` + `remote_access` | 115 | `HIGH_RISK` | step-up |

Two contrasts are worth pausing on:

- **D2 vs D3.** A rooted phone running the *genuine* app (40) is `LOW_RISK` and
  allowed — kseal doesn't punish power users. A *repackaged* build (60) that also
  fails attestation (70) is `CRITICAL` and denied. The system reacts to forgery,
  not to environment.
- **D4 vs D5.** Two fraud-vector combinations, two different levels — 75
  (`MEDIUM_RISK`) vs 115 (`HIGH_RISK`) — both resolved to a step-up in
  Meridian's `STEP_UP` mode. In `BLOCK` mode, D5's `HIGH_RISK` would become a
  hard deny. Same signals, different posture: the tenant chooses how aggressive
  to be.

The mechanics of *why* the decision is server-side (and why that's safe against a
lying client) are in
[Why the trust decision lives on the server](trust-on-the-server.md). The fraud
vectors behind D4/D5 get their own post:
[Five fraud vectors](five-fraud-vectors.md).
