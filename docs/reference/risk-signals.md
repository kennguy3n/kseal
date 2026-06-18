# Risk signals, scoring & trust decisions

This page is the authoritative reference for how kseal turns device observations
into a trust decision. Every value is taken directly from
`server/shared/risk/risk.go` and the Rust core's `risk.rs`, which pin the same
contract from both sides. The worked examples use the canonical reference
deployment, **Meridian Pay** (see [`reference/fixtures/`](fixtures/README.md)).

The pipeline has four stages:

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

---

## 1. Two bit layouts, one mandatory translation

The device and the server use **different** bit layouts. The same numeric
position means different things on each side — wire bit 4 is `DEBUGGER`, but
server bit 4 is `APP_TAMPER`. A device bitset is therefore **never** scored
raw: it must first pass through `FromWire`, which remaps each wire bit to the
server bit it means and drops wire bits with no server meaning.

### Device / wire bits (0–20)

These are the 21 positions a device SDK can set, exactly as carried in the proto
`RiskBitset` and `TelemetryEvent.risk_bits`:

| Bit | Wire signal | Maps to server bit |
|---|---|---|
| 0 | `wireRoot` | `BitRootJailbreak` |
| 1 | `wireJailbreak` | `BitRootJailbreak` |
| 2 | `wireEmulator` | `BitEmulator` |
| 3 | `wireSimulator` | `BitEmulator` |
| 4 | `wireDebugger` | `BitDebugger` |
| 5 | `wireHooking` | `BitHooking` |
| 6 | `wireTamper` | `BitAppTamper` |
| 7 | `wireAppIntegrity` | `BitAppTamper` |
| 8 | `wireNetworkMITM` | `BitNetworkMITM` |
| 9 | `wireEnvironment` | `BitEnvironmentRisk` |
| 10 | `wireProxy` | `BitEnvironmentRisk` |
| 11 | `wireUserCA` | `BitNetworkMITM` |
| 12 | `wirePinningFailure` | `BitNetworkMITM` |
| 13 | `wireAttestationFail` | `BitAttestationFail` |
| 14 | `wireSecureHWMissing` | `BitDeviceIntegrity` |
| 15 | `wireRepackaged` | `BitAppTamper` |
| 16 | `wireScreenCapture` | `BitScreenCapture` |
| 17 | `wireOverlayAbuse` | `BitOverlayAbuse` |
| 18 | `wireAccessibility` | `BitAccessibilityAbuse` |
| 19 | `wireMaliciousIME` | `BitMaliciousIME` |
| 20 | `wireRemoteAccess` | `BitRemoteAccess` |

This table is the single source of truth for the wire→server contract and is
pinned by `TestWireToServerContract` (Go) and `TestRiskBitLayoutContract`
(Rust). The layout is append-only: positions are never renumbered, only added.

### Server bits and weights

The server layout is what scoring, levels, and policy weights all speak. Each
bit carries a default severity weight (a policy may override any weight):

| Server bit | Position | Default weight | Source of the signal |
|---|---|---|---|
| `BitRootJailbreak` | 0 | **40** | device |
| `BitDebugger` | 1 | **25** | device |
| `BitEmulator` | 2 | **20** | device |
| `BitHooking` | 3 | **35** | device |
| `BitAppTamper` | 4 | **60** | device |
| `BitAttestationFail` | 5 | **70** | attestation |
| `BitNetworkMITM` | 6 | **30** | device |
| `BitAccountRisk` | 7 | **20** | server |
| `BitDeviceIntegrity` | 8 | **45** | attestation / device |
| `BitAppUnrecognized` | 9 | **65** | attestation |
| `BitEnvironmentRisk` | 10 | **15** | device |
| `BitScreenCapture` | 11 | **30** | device (fraud vector) |
| `BitOverlayAbuse` | 12 | **35** | device (fraud vector) |
| `BitAccessibilityAbuse` | 13 | **40** | device (fraud vector) |
| `BitMaliciousIME` | 14 | **25** | device (fraud vector) |
| `BitRemoteAccess` | 15 | **45** | device (fraud vector) |
| `BitFleetAnomaly` | 32 | **50** | server (fleet) |

`BitFleetAnomaly` sits at position 32 — well clear of the device range (0–20) —
because it can never be reported by a device. It is derived server-side when a
(tenant, app) population shows a coordinated surge of an abuse signal above its
learned baseline.

---

## 2. Fuse — union local and attestation signals

Once device bits are in the server layout, `Fuse` unions them with bits derived
from platform attestation (Play Integrity / App Attest / DeviceCheck) and any
server-side signals. Fusion is a pure union: any source asserting a risk keeps
it set.

```
fused = FromWire(device_bits) | attestation_bits
```

---

## 3. Score — weighted, saturating

`Score` sums the weight of every set bit. Addition **saturates** at the 32-bit
maximum so a hostile or misconfigured policy can never overflow the score and
wrap it down to a misleadingly low value. The Rust core mirrors this with
`u32::saturating_add`.

```
score = Σ weight(bit)  for each set bit, clamped to u32::MAX
```

---

## 4. Level — score to trust level

Default thresholds map a score to a trust level. A policy may override any
threshold by name (e.g. `HIGH_RISK`).

| Trust level | Minimum score |
|---|---|
| `CRITICAL` | **≥ 130** |
| `HIGH_RISK` | **≥ 90** |
| `MEDIUM_RISK` | **≥ 50** |
| `LOW_RISK` | **≥ 20** |
| `TRUSTED` | **< 20** |

---

## 5. Decision — level to enforcement

The product rule is **observe → step-up → block**. The decision depends on both
the trust level and the tenant's enforcement mode:

| Trust level | `OBSERVE` | `STEP_UP` | `BLOCK` |
|---|---|---|---|
| `CRITICAL` | allow | **deny** | **deny** |
| `HIGH_RISK` | allow | **step-up** | **deny** |
| `MEDIUM_RISK` | allow | **step-up** | **step-up** |
| `LOW_RISK` | allow | allow | allow |
| `TRUSTED` | allow | allow | allow |

`OBSERVE` never denies anything — it only records risk, which is how a tenant
rolls kseal out safely before turning on enforcement. Meridian Pay runs in
`STEP_UP` (see [`reference/fixtures/control/policy.json`](fixtures/control/policy.json)).

As risk rises, the server also tells the SDK which probes to run before its next
refresh via `NextChecks`: nothing extra at `TRUSTED`/`LOW_RISK`, root + debugger
at `MEDIUM_RISK`, and root + debugger + hooking + app-integrity at
`HIGH_RISK`/`CRITICAL`.

---

## 6. Worked examples (Meridian Pay)

These are the canonical scenarios from
[`reference/fixtures/scenarios.json`](fixtures/scenarios.json). Each one is the
exact arithmetic the server runs.

### D1 — a clean device (`TRUSTED`, allow)

No risk bits set.

```
fused  = 0
score  = 0
level  = TRUSTED        (score < 20)
mode   = STEP_UP
result = ALLOW
```

### D3 — repackaged build on a rooted phone failing attestation (`CRITICAL`, deny)

The device reports `wireTamper` (bit 6), which `FromWire` maps to
`BitAppTamper`. Platform attestation fails, contributing `BitAttestationFail`.

```
device wire bits   = { wireTamper }                 → BitAppTamper
attestation bits   = { BitAttestationFail }
fused              = BitAppTamper | BitAttestationFail
score              = 60 (AppTamper) + 70 (AttestationFail) = 130
level              = CRITICAL          (score ≥ 130)
mode               = STEP_UP
result             = DENY
next_checks        = root, debugger, hooking, app-integrity
```

The decision document for this scenario is
[`reference/fixtures/trust/trust-decision.json`](fixtures/trust/trust-decision.json),
and the resulting CRITICAL event is what flows to Meridian's Splunk in
[`reference/fixtures/egress/siem-event.json`](fixtures/egress/siem-event.json).

The point the example makes: a single device bit (tamper, 60) is `MEDIUM_RISK`
on its own and would only trigger a step-up. It is the **fusion** with the
server-side attestation failure (70) that crosses the `CRITICAL` threshold and
denies the action — exactly the server-side-trust property kseal is built on. A
tampered client cannot talk its own way out of a denial, because the deciding
weight comes from a signal it does not control.
