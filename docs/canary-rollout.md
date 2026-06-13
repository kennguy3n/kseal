# kseal — Canary Rollout & Auto-Rollback

Canary rollout delivers a **candidate policy** to a deterministic percentage of
an app's instances, tracks the candidate cohort's health from existing
guardrail signals, and **auto-rolls-back** to the last-known-good policy when a
guardrail threshold is breached. Rollouts default to 0% and are flag-gated.

Parity: incumbents offer staged config delivery; kseal ties it to real-time
guardrail health with automatic, audited rollback.

## Deterministic bucketing

Candidate selection is a pure function of the rollout percent and a tenant-
scoped instance hash — no DB round-trip on the hot path:

```
bucket    = SHA256(tenant_id || 0x00 || app_id || 0x00 || instance_id)[:8] % 100
candidate = bucket < percent
```

- **Deterministic**: an instance never flips between candidate and stable across
  config fetches for a given percent.
- **Monotonic in percent**: raising the percent only adds instances to the
  cohort; it never removes one.
- **Tenant-scoped**: the same `instance_id` under different tenants/apps gets
  independent buckets, so cohorts never correlate across tenants.
- **Fail-safe**: an empty `instance_id` (or `percent = 0`) stays on stable.

`instance_id` is an opaque, rotating, tenant-scoped identifier supplied on
`ConfigRequest`; it is never a device fingerprint.

## Hot-path selection

The data plane keeps a **lock-free, atomic-pointer snapshot** of active
rollouts (`canary.Registry`). `ConfigService.GetConfig` calls `Cohort(...)` to
pick the candidate or stable policy with zero DB round-trips; resolving a
candidate is fail-safe (any error falls back to the active policy, so a rollout
misconfiguration never denies config).

## Health & auto-rollback

`TrustService` records each request's allow/deny outcome against the cohort's
policy id, feeding the guardrails detector. A background controller sweeps
active rollouts and rolls one back when:

```
samples >= MinSamples  AND  block_rate > rollback_threshold   (default 0.05)
```

Rollback reverts to the stable policy, zeroes the percent, records the observed
`block_rate`/`sample_count`, and emits a `canary.rollback` audit event. The
`MinSamples` floor prevents rollback on statistically meaningless traffic. The
controller also refreshes the in-memory snapshot each sweep.

## RPCs (`ComplianceService`)

| RPC | Request → Response | Notes |
|---|---|---|
| `SetCanaryRollout` | `SetCanaryRolloutRequest{tenant_id, app_id, candidate_policy_id, percent, rollback_threshold}` → `SetCanaryRolloutResponse{status}` | Validates candidate belongs to app; resolves stable from the active policy |
| `GetCanaryStatus` | `GetCanaryStatusRequest{tenant_id, app_id}` → `GetCanaryStatusResponse{status}` | State + observed health for the console |
| `PromoteCanary` | `PromoteCanaryRequest{tenant_id, app_id}` → `PromoteCanaryResponse{status}` | Activates candidate as the new active policy; marks promoted |
| `RollbackCanary` | `RollbackCanaryRequest{tenant_id, app_id, reason}` → `RollbackCanaryResponse{status}` | Manual withdrawal to last-known-good |

`CanaryStatus.state` ∈ `{ACTIVE, PROMOTED, ROLLED_BACK}`.

## Flag-gating

Candidate selection and the health feed are gated by the `canary_rollout`
feature flag (`KSEAL_FEATURE_FLAGS`), default off. With the flag off every
instance is served the stable policy and no health is recorded — default
behavior on `main` is unchanged.
