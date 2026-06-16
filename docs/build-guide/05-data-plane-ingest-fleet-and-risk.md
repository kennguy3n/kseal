# Chapter 5 — The data plane: ingest, fleet anomaly & risk fusion at scale

> **The decision:** Per-instance attestation answers "is *this* device trustworthy?" — but
> it's blind to the population. How do you spot a coordinated attack across thousands of
> installs **without** a data lake, an analyst, or a per-user identifier?

This is the chapter where a "dashboard" becomes "a product that protects you."

---

## The data plane's job

Everything high-volume lives here (`server/data-plane/`): edge ingest, attestation
verification (`attestation/`), trust sessions (`trust/`), event ingest (`ingest/`), risk
fusion, fleet anomaly detection (`fleet/`), canary control (`canary/`), guardrails
(`guardrails/`), query (`query/`), and fan-out to webhooks (`webhook/`) and SIEM (`siem/`).
It is **eventually consistent and never the source of truth for secrets** — it executes
signed policy from the control plane, it doesn't author it.

The production broker (Kafka/Redpanda), analytics store (ClickHouse) and OTLP are delivered
behind interfaces and enabled via env vars (`KSEAL_BROKER` / `KSEAL_ANALYTICS` /
`KSEAL_OTLP_ENDPOINT`), defaulting to an in-process broker + in-memory store so a small tenant
pays for none of it. That "heavy parts off by default, fail-closed" posture is what keeps the
plane operable by one engineer.

---

## Risk fusion: bits in, decision out

Ingest normalizes every event to the stable risk bitset from
[Chapter 3](03-device-plane-rasp-and-rust-core.md), then **fuses** the device-reported bits
with the platform-attestation verdict and scores them against the active policy. Scoring is
the `policy_evaluate` path (~49 ns on device, the same logic server-side): weighted signal
bits → a composite score → a trust band (TRUSTED / MEDIUM / HIGH / CRITICAL) → an enforcement
mode (OBSERVE / STEP_UP / DENY). The client never gets a vote; it only contributes signals.

A subtle but important rule: **the server can fuse signals the client didn't report.** The
prime example is the `FLEET_ANOMALY` bit below — derived entirely server-side from population
behavior and folded into newly arriving attestations for a hot cohort.

---

## Fleet Anomaly Guard: population detection at O(1)/event

This is the marquee data-plane capability and the clearest example of the *zero-config*
constraint shaping the design. The engine (`server/data-plane/fleet/engine.go`) continuously
learns each app's normal prevalence of abuse signals, scoped per **(tenant, app, build,
region)** cohort, and watches for two kinds of break:

- a **per-signal surge** — e.g. `root_jailbreak` prevalence spiking far above the cohort's
  learned baseline, and
- a **volume-velocity spike** — a cohort's attestation *volume* exploding above baseline,
  which catches a coordinated flood even when each individual client looks clean.

When a cohort breaks, the engine fuses a server-derived `FLEET_ANOMALY` bit into **newly
arriving** attestations for that cohort — a graduated **auto step-up**, not a blunt block, so
legitimate users in a hot cohort aren't locked out.

### The constraints that dictate the implementation

The SME economics from [Chapter 1](01-thesis-and-business-case.md) make four demands, and each
maps to a concrete design choice:

| Requirement | Design choice |
|---|---|
| **Zero-config** | Baselines are *learned* (`foldBaseline` / `observeLocked`), not declared. No thresholds to tune. |
| **Cheap at scale** | **O(1) per event**, in-process — no extra service, no per-event query. |
| **Bounded memory** | Sharded, LRU-evicted cohort state — fits thousands of tenants × millions of apps without a per-cohort cost explosion. |
| **No privacy debt** | **Aggregates only** — no new per-user identifier is introduced to do population detection. |
| **Not spoofable** | Region is trusted from edge headers **only when the operator opts in**, so an attacker hitting the server directly can't fabricate cohorts to slip under a baseline. |

### Proven both ways

The behaviour is a unit test, not a demo artifact:
`server/data-plane/fleet/engine_test.go` has `TestBaselineLearnThenSurge` (learn a clean
baseline, then catch the surge) **and** `TestUnobservedScopeIsClean` (don't cry wolf on quiet
cohorts). The [FitPulse chapter](../showcase/02-fitpulse-noops-sme.md) is this test, driven
live: 320+ root attestations against `fitpulse-3.9` in five minutes → a `Surge` verdict at
422 observations → auto step-up, with no human in the loop.

---

## Why not "just use an account-abuse platform"?

Castle/Arkose are genuinely strong at population abuse — on that single axis they're a peer or
better. But they're **account-abuse platforms that expect an analyst to tune them**, and they
don't also give you mobile attestation, app-integrity, a kill switch and compliance evidence in
one product. For the NoOps buyer, "buy Arkose and hire an analyst" isn't an answer — so the
data plane has to *be* the analyst, zero-config. That requirement is exactly why the engine
learns baselines instead of exposing knobs.

---

## The business read

- **Fleet detection is the capability that justifies the platform**, not the per-instance
  check. Anyone can ship root detection; "we catch the coordinated wave automatically, with no
  analyst" is the thing the SME literally cannot buy elsewhere as one product.
- **O(1)/event and aggregates-only is what makes it *sellable* to that buyer** — it costs
  cents at 100M MAU ([Chapter 8](08-cost-scale-and-noops-economics.md)) and creates no privacy
  liability ([Chapter 7](07-privacy-and-compliance.md)), instead of an enterprise contract plus
  a DPIA headache.
- **"Heavy parts off by default" is the pricing ladder.** A small tenant runs the in-process
  path for free; a large one flips on Kafka/ClickHouse. The architecture *is* the tiering.

Next: [Chapter 6 — The control plane](06-control-plane-registry-policy-audit.md), the source of
truth that signs everything the other planes execute.
