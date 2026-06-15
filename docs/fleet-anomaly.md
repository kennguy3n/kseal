# kseal — Fleet Anomaly Guard

Per-instance attestation is blind to coordinated attacks where every individual
proof is cryptographically valid — an emulator farm, a mass account-creation
wave, or a leaked/repackaged build spreading across thousands of devices. Each
device self-reports clean and passes platform attestation, so a stateless
`Fuse → Score → Level → Decision` path judges it in isolation even when 10,000
siblings on the same build just appeared from one region in five minutes.

**Fleet Anomaly Guard** closes that gap. It is a zero-config, in-process engine
that learns each **cohort's** baseline behaviour and, on a surge, fuses a
server-derived `FLEET_ANOMALY` risk bit into newly joining clients — a graduated
step-up, never a hard block. This is the population-level abuse signal that
Approov / Castle / Arkose monetise, delivered without analysts or ops.

Parity: incumbents sell behavioural/anomaly analytics as a premium tier. kseal
ships it as a default-off flag that needs no tuning, no extra identifiers, and no
new infrastructure.

## Cohorts

A cohort is a `(tenant, app, build_hash, region)` tuple, so the engine answers
"this *build* / this *region* is under coordinated attack" rather than only
"this app". `region` is best-effort, populated from the edge country header when
the request arrives through a CDN (`Cf-Ipcountry`, `X-Vercel-Ip-Country`,
`X-Geo-Country`, `X-Country-Code`, `X-Appengine-Country`); an empty region simply
degrades to a build-level cohort. `build_hash` comes from the attestation
request. No new identifier is introduced and no per-user state is kept — the
engine counts already-collected, non-PII risk bits and arrival volume.

## Two detectors

For each cohort the engine keeps a sliding window (`Window`, default 5m) split
into `Buckets` (default 10) fixed slices, plus one EWMA baseline per watched
signal and one EWMA baseline for arrival volume. Each completed bucket folds into
the baselines as it ages out of the window, so "normal" is learned continuously
and a sustained new level eventually becomes the baseline.

### 1. Per-signal surge

For each watched signal the current-window rate is compared to its learned
baseline:

```
seeded:    anomalous = current >= AbsoluteFloor  AND  current >= baseline * SurgeFactor
cold-start: anomalous = current >= ColdStartFloor      (no baseline learned yet)
gate:      window must hold >= MinSamples attestations
```

`AbsoluteFloor` (default 0.15) stops a tiny baseline (0.1% tripling to 0.3%) from
raising noise; `SurgeFactor` (default 3.0) requires a real multiple over normal;
`ColdStartFloor` (default 0.30) guards brand-new cohorts with no baseline.
Watched signals (server risk-bit layout): `root_jailbreak`, `emulator`,
`hooking`, `app_tamper`, `attestation_fail`, `device_integrity`,
`app_unrecognized`.

### 2. Volume velocity

A cohort's arrival volume spiking far above its own normal trips an anomaly even
when **every signal looks individually clean** — the "thousands of siblings
appear at once" flood:

```
seeded:    anomalous = window_volume >= VelocityMinVolume
                       AND window_volume >= projected_baseline_volume * VelocityFactor
cold-start: anomalous = window_volume >= VelocityColdVolume   (brand-new cohort)
```

`projected_baseline_volume = volBaseline * Buckets`. Defaults: `VelocityFactor`
4.0, `VelocityMinVolume` 200, `VelocityColdVolume` 500. The reported
`VelocityRatio` is `window_volume / projected_baseline_volume` (0 on a cold-start
trip, where no baseline exists yet).

## Performance & memory

Designed to hold at 5,000 tenants × millions of apps × tens of millions of MAU:

- **O(1) per observed attestation**, O(buckets) per assessment.
- **Fixed memory per cohort**: a small bucket ring plus one EWMA per watched
  signal and one for volume.
- **Bounded total memory**: cohorts live in 256 sharded LRU maps capped at
  `MaxScopes` (default 200,000); idle cohorts are evicted, never leaked.
- **In-process, per-replica**: each replica observes its own slice of traffic;
  the *relative* baseline/surge model still fires on every replica that sees a
  real surge, with zero cross-replica coordination cost. A shared aggregator is a
  possible future extension; the per-replica model is intentional for the
  NoOps/low-cost target.

## Wiring

`TrustService.VerifyAttestation` calls `Observe(tenant, app, build, region, fused, now)`
then `Assess(...)`; when the cohort is anomalous it fuses `risk.BitFleetAnomaly`
into the minted session's risk **before** scoring, so the new client is stepped
up by the active policy's weight for that bit. The fused bits passed to the
engine are already in the **server** risk-bit layout (see
[risk-bit-contract.md](risk-bit-contract.md)), so signal masks match the rest of
the decision path.

## Observability

- **Prometheus**: `kseal_fleet_anomaly_active` gauge, labelled
  `{tenant, app, build, region}`, set to 1 for each anomalous cohort by a
  background sampler and cleared when a cohort recovers.
- **OTel**: `trust.VerifyAttestation` spans carry `fleet.anomalous`,
  `fleet.signals`, and `fleet.velocity_surge` attributes.
- **Console**: the tenant **Overview** surfaces a *Fleet anomalies* panel listing
  each anomalous cohort with its build, region, surging signals, surge ratio,
  velocity badge, and observed volume — populated from
  `GetTenantOverviewResponse.active_fleet_anomalies`.

## Configuration

All knobs have safe NoOps defaults; an SME never has to tune anything. Optional
environment overrides (see `fleet.ConfigFromEnv`):

```
KSEAL_FLEET_WINDOW              e.g. "5m"
KSEAL_FLEET_BUCKETS             integer > 0
KSEAL_FLEET_SURGE_FACTOR        float > 1
KSEAL_FLEET_ABSOLUTE_FLOOR      float in (0,1]
KSEAL_FLEET_COLDSTART_FLOOR     float in (0,1]
KSEAL_FLEET_MIN_SAMPLES         integer > 0
KSEAL_FLEET_BASELINE_ALPHA      float in (0,1]
KSEAL_FLEET_VELOCITY_FACTOR     float > 1
KSEAL_FLEET_VELOCITY_MIN_VOLUME integer > 0
KSEAL_FLEET_VELOCITY_COLD_VOLUME integer > 0
KSEAL_FLEET_MAX_SCOPES          integer > 0
```

## Flag-gating

Observation and fusion are gated by the `fleet_anomaly` feature flag
(`KSEAL_FEATURE_FLAGS`), default off. With the flag off the engine is a no-op and
the trust decision is byte-for-byte the per-instance path on `main`. A nil engine
(guard never attached) disables it entirely.
