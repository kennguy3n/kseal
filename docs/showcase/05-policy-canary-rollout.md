# Policy canary rollout — shipping a trust-policy change with a seatbelt

**Meridian Pay team:** Release engineering. Owns config/policy changes and is wary of the
change that takes down checkout for everyone at once.
**Job to be done:** *"Let me roll a stricter trust policy out to a slice of traffic, watch its
health, and have the system automatically revert if it starts hurting real users — so I can
ship on a Friday."*

The deployment is the canonical [Meridian Pay reference](../reference/fixtures/README.md):
tenant `meridian`, apps `pay-android` and `merchant`, regions US/DE/BR/IN/SG.

---

## The problem

A trust/risk policy is production config with teeth. Make it too strict and you start blocking
legitimate customers at checkout; make the change to 100% at once and you find out the hard
way, at full blast. The release engineer wants the same discipline they already have for app
rollouts — **stage to a percentage, watch a guardrail metric, auto-revert on regression** — but
for the *server-side trust policy*, and without standing up a separate experimentation platform
to get it.

---

## What the release team does in kseal

Meridian's stable, last-known-good policy for `pay-android` is the one in
[`control/policy.json`](../reference/fixtures/control/policy.json): enforcement mode
`STEP_UP`, all fraud-vector modules enabled, with the thresholds every scenario in
[`scenarios.json`](../reference/fixtures/scenarios.json) is scored against:

```json
"enforcement_mode": "STEP_UP",
"thresholds": { "CRITICAL": 130, "HIGH_RISK": 90, "MEDIUM_RISK": 50, "LOW_RISK": 20 }
```

To tighten enforcement — say, raising friction on a fraud vector — the engineer stages a
**candidate policy** to a slice of traffic with an armed guardrail rather than flipping it for
everyone:

- **Rollout %**: only a fraction of instances are deterministically bucketed into the candidate
  cohort; the rest stay on the stable policy.
- **Candidate block rate vs. rollback threshold**: a controller continuously measures the
  candidate cohort's block rate over a trailing window. If it crosses the threshold *with
  enough samples to be statistically meaningful*, kseal **auto-rolls-back** to the
  last-known-good policy.
- **Tamper-evident record**: the revert (and any manual promotion) writes a hash-chained audit
  entry recording the breach and the action — no human in the loop, no 2 a.m. page.

The mechanism: kseal deterministically buckets each instance into candidate or stable,
attributes every live trust decision to its cohort, and the controller drives the guardrail.
Promotion and rollback are also available as explicit controls when the engineer wants to drive
it manually. Both the candidate and stable policies ride the **signed config envelope** in
[`control/config-envelope.json`](../reference/fixtures/control/config-envelope.json), so the
device verifies each policy offline against the pinned key before applying it.

This is the release engineer's seatbelt: stage small, measure automatically, revert
automatically, and keep a tamper-evident record of what happened.

---

## How the incumbents handle this

| Capability | kseal | Approov | Guardsquare/Appdome | Castle/Arkose |
|---|---|---|---|---|
| Staged % rollout of a **server-side trust policy** | **Built-in** | Limited (policy/rotation) | App-config oriented | Rule changes, varies |
| Block-rate guardrail with **automatic** rollback | **Built-in** | DIY | DIY | Manual/analyst |
| Deterministic candidate/stable cohorting per instance | **Yes** | No | No | Varies |
| Auto-revert writes a tamper-evident audit entry | **Yes** | DIY | DIY | Partial |

Progressive delivery is a well-understood idea — but having it built into the **trust-policy**
layer, with an automatic block-rate guardrail and an audit-logged auto-rollback, is something
lean teams would otherwise approximate by bolting a feature-flag/experimentation tool onto a
system that wasn't designed for it.

---

## Back-tested evidence

The seatbelt is only worth trusting if it's been crash-tested — and the canary controller is
tested in **both** directions (full numbers in
[Evidence & back-testing](evidence-and-backtesting.md), perf in
[benchmarks](../reference/benchmarks.md)):

- **Rollback fires when it should — and not when it shouldn't.** `controller_test.go` asserts
  the guardrail rolls back **above** the block-rate threshold *and* is suppressed **below** the
  minimum-sample count, so a few unlucky early decisions can't trigger a spurious revert.
- **Bucketing is deterministic and stable.** `bucket_test.go` proves
  `InCanary(tenant, app, instance, percent)` is deterministic per instance, monotonic in the
  percentage, and independent across tenants — so an instance doesn't flip cohorts between
  requests, and one tenant's rollout can't perturb another's.
- **Signed, cacheable config underneath.** The candidate/stable policies ride the same
  Ed25519-signed envelope proven by `e2e_config_test.go` (verify + ETag caching + TTL + version
  rotation) — config verification costs **~54 µs** on device and only runs when a new signed
  config actually arrives.

---

## Why it wins for the release team

- **Ship without holding your breath.** Partial exposure, automatic guardrail, instant revert
  to a known-good policy.
- **No experimentation platform required.** The canary lives in the trust layer itself.
- **Always a record.** Every promotion or auto-rollback is an audit entry, so the change
  history is defensible.

> JTBD met: *roll a stricter policy to a slice of traffic, let the system watch and auto-revert
> on regression, and ship with confidence — on a Friday.*
