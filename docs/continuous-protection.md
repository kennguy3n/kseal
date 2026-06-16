# kseal — Continuous Protection & Active Response

Trust in kseal is established **on demand** (`GetNonce` → `VerifyAttestation` →
signed trust token → `ValidateRequestProof`) and the SDK makes **no network I/O
at launch** (the "<40 ms startup" invariant). Continuous protection adds an
**opt-in** periodic re-attestation loop plus host-app **active-response hooks**,
without weakening either invariant: it is OFF by default and the SDK never
kills, locks, or wipes on its own.

## Opt-in re-attestation cadence

`PolicyConfig` carries an additive field:

```proto
// proto/kseal/v1/config.proto
message PolicyConfig {
  // ... fields 1-6 ...
  uint32 reattest_interval_secs = 7; // 0 (default) = continuous mode OFF
}
```

- **`0` (default)** — continuous mode is entirely off. Behavior on `main` is
  unchanged and there is no launch-time network call. Existing policies (which
  never set the field) decode it as `0`.
- **`> 0`** — the host may opt in by calling `startContinuousProtection()`. The
  SDK schedules a background heartbeat at that cadence (and the host can also
  pump a cycle on app foreground via `onAppForeground()`), re-running probes and
  re-validating.

The cadence is sourced from the signed policy, so it ships through the same
verified channel as the rest of the config; the SDK reads it locally
(`reattestIntervalSecs`) and never derives it from an unauthenticated source.
Even with a positive interval, **nothing runs until the host explicitly opts
in** — loading a policy does not start a timer.

### Escalation (coverage rises with risk)

Each cycle:

1. re-runs probes and recomputes the trust level + decision locally,
2. fires the `onTrustDecision` hook (below),
3. re-validates the signed config (`refreshConfig()` — provider-driven; the
   default provider falls back to cache, so still no network), and
4. at **`MEDIUM_RISK` or above** also pulls and applies the latest signed kill
   switch (`refreshKillSwitch()`).

This mirrors the server's `NextChecks()` escalation: coverage and
re-validation frequency rise with locally-computed risk rather than running the
heaviest checks unconditionally.

## Active-response hooks (`onTrustDecision`)

The server computes the trust decision (`DECISION_ALLOW` / `DECISION_STEP_UP` /
`DECISION_DENY`) via `risk.Decision(level, mode)`; the SDK **consumes** it and
surfaces it — it does not change the server logic. The same `risk.Decision`
mapping is mirrored in the shared Rust core (`decision(risk_bits)`) so the
re-attestation loop can compute a decision locally between server round-trips.

`onTrustDecision(level, decision)` is delivered from two places:

- **`authorizeRequest(...)`** — the **real server decision** returned by
  `ValidateRequestProof`, and
- the **re-attestation cycle** — the locally re-computed decision.

The default callback is a **no-op**. The SDK never enforces the decision; the
host decides what `STEP_UP` (e.g. force MFA / biometric re-auth) and `DENY`
(e.g. lock sensitive screens, enter read-only mode) mean for its UX.

```kotlin
// Android
sdk.onTrustDecision = { level, decision ->
    when (decision) {
        Decision.STEP_UP -> requireBiometricReauth()
        Decision.DENY    -> lockSensitiveScreens()
        else             -> Unit
    }
}
sdk.startContinuousProtection() // no-op unless reattest_interval_secs > 0
```

```swift
// iOS / macOS
sdk.onTrustDecision = { level, decision in
    switch decision {
    case .stepUp: presentReauthSheet()
    case .deny:   enterReadOnlyMode()
    default:      break
    }
}
sdk.startContinuousProtection()
```

## Kill-switch surfacing

The forced-degrade surface (`isKilled`, `onKillSwitchChanged`,
`applyKillSwitch`, `refreshKillSwitch`) is documented in
[kill-switch.md](kill-switch.md#sdk-surfacing-iskilled). It is verified on
device against the config anchor and is fail-safe: a forged or absent command
never disables the app.

## Platform mechanics

| | Android | iOS / macOS |
|---|---|---|
| Scheduler | `ScheduledExecutorService` (daemon thread `kseal-reattest`), no coroutines / WorkManager dependency | `DispatchSourceTimer` on a dedicated serial queue |
| Opt-in | `startContinuousProtection(): Boolean` (false unless interval > 0) | `startContinuousProtection() -> Bool` |
| Stop | `stopContinuousProtection()` | `stopContinuousProtection()` |
| Foreground pump | `onAppForeground()` | `onAppForeground()` |

The per-cycle work is a pure, dependency-injected method
(`runReattestCycle()`), so unit tests drive escalation deterministically
without the timer or the native library.
