# kseal — Cost Model (10M / 100M / 300M MAU)

A bottom-up infrastructure cost model for the kseal **data plane** at three
scales — **10M, 100M, and 300M MAU** — with explicit formulas and per-resource
line items. It quantifies the [Unit Economics](../PROPOSAL.md#unit-economics)
thesis: a **sparse, compressed, sampled** telemetry design (the "good design")
versus a chatty heartbeat-and-raw design (the "naive design"), and shows where
the ~20× raw-ingest gap does and does not translate into blended infrastructure
cost.

All dollar figures are **order-of-magnitude planning estimates** using
representative public-cloud rates (below). They exist to compare *designs* and
*scales*, not to predict a specific cloud bill. Tie-in:
[ARCHITECTURE.md cost knobs](../ARCHITECTURE.md#how-to-stay-lightweight) and the
[Pricing Model](../PROPOSAL.md#pricing-model-direction).

## Table of Contents

- [Assumptions and Rates](#assumptions-and-rates)
- [Event Volume Math](#event-volume-math)
- [Per-Resource Formulas](#per-resource-formulas)
- [Good-Design Cost by Scale](#good-design-cost-by-scale)
- [Naive vs Good Comparison](#naive-vs-good-comparison)
- [What Dominates Cost (Sensitivity)](#what-dominates-cost-sensitivity)
- [Mapping to Cost-Control Rules](#mapping-to-cost-control-rules)
- [Implications for Pricing](#implications-for-pricing)

---

## Assumptions and Rates

These are the knobs. Change them and the formulas below recompute.

### Workload knobs

| Knob | Symbol | Good design | Naive design | Source |
|---|---|---|---|---|
| DAU / MAU ratio | `r` | 0.30 | 0.30 | [Unit Economics](../PROPOSAL.md#unit-economics) (100M MAU → 30M DAU) |
| Events per DAU per day | `E` | 2 | 20 | [Event math](../PROPOSAL.md#unit-economics) |
| Bytes per event (raw) | `B` | 250 | 500 | [Event math](../PROPOSAL.md#unit-economics) |
| Peak factor (diurnal) | `P` | 3× | 3× | Planning assumption |

### Efficiency knobs

| Knob | Value | Rationale |
|---|---|---|
| zstd wire/cold compression | 4× | Compact protobuf + shared dictionaries ([compression](../ARCHITECTURE.md#compression)) |
| ClickHouse on-disk columnar compression | 8× | Low-cardinality risk bits/enums compress very well |
| Hot retention (ClickHouse) | 30 days | Hot/cold tiering ([store compliance](../ARCHITECTURE.md#store-compliance)) |
| Cold retention (S3) | 365 days | Default cold window (regionally configurable) |
| Per-event pipeline throughput | 2,000 events/s/vCPU | Ingest + risk fusion + write, Go workers |
| Index/overhead multiplier (hot) | 1.5× | Indices, marks, replication headroom |
| Peak concurrent trust sessions | `r × MAU × 0.10` | ~10% of DAU online at peak |

### Rate card (representative USD)

| Resource | Rate |
|---|---|
| Object storage (S3 Standard-IA, cold) | $0.0125 / GB-month |
| Hot block storage incl. replication (ClickHouse on gp3-class) | $0.10 / GB-month |
| Compute (Go worker vCPU) | $30 / vCPU-month (~$0.04/vCPU-hr) |
| Streaming (Kafka/Redpanda) | $300/month cluster floor + $0.10 / GB-month buffered |
| CDN egress (config) | $0.05 / GB delivered |
| Managed Redis | $35 / GB-month (+ small-node floor) |
| KMS | $0.03 / 10k operations |

> Cloud **ingress is typically free**, so client→edge bandwidth is modeled at
> ~$0; the cost of receiving events shows up as **compute + streaming +
> storage**, not bandwidth.

---

## Event Volume Math

Daily raw ingest is the spine everything else hangs off:

```text
DAU            = r × MAU
daily_events   = DAU × E
daily_raw_B    = daily_events × B
monthly_raw_GB = daily_raw_B × 30 / 1e9
avg_eps        = daily_events / 86400
peak_eps       = avg_eps × P
```

Applying the **good-design** knobs (`r=0.30, E=2, B=250`):

| MAU | DAU | daily_events | daily_raw | monthly_raw | avg eps | peak eps |
|---|---|---|---|---|---|---|
| 10M | 3M | 6M | 1.5 GB/day | 45 GB | 69 | ~210 |
| 100M | 30M | 60M | 15 GB/day | 450 GB | 694 | ~2,100 |
| 300M | 90M | 180M | 45 GB/day | 1,350 GB | 2,083 | ~6,250 |

The 100M row reproduces the **15 GB/day** figure from
[Unit Economics](../PROPOSAL.md#unit-economics). Note how *low* the event rate is
— good-design ingest at 100M MAU is only ~2k events/s at peak, which is why
**compute and cluster floors dominate, not the data itself.**

Applying the **naive** knobs (`E=20, B=500`):

| MAU | daily_raw | monthly_raw | peak eps |
|---|---|---|---|
| 10M | 30 GB/day | 900 GB | ~2,100 |
| 100M | 300 GB/day | 9,000 GB | ~20,800 |
| 300M | 900 GB/day | 27,000 GB | ~62,500 |

The 100M naive row reproduces the **~300 GB/day** figure — a **20×** raw-ingest
gap versus good design.

---

## Per-Resource Formulas

| Resource | Formula (monthly) |
|---|---|
| **Ingest bandwidth** | `≈ $0` (ingress free); compressed wire = `daily_raw / 4` |
| **Compute** | `max(HA_floor, ceil(peak_eps / 2000)) × $30`, `HA_floor = 4 vCPU` |
| **Streaming (Kafka)** | `$300 + (daily_raw/4 × buffer_days) × $0.10`, `buffer_days = 3` |
| **Hot storage (ClickHouse)** | `(daily_raw × hot_days / 8) × 1.5 × $0.10`, `hot_days = 30` |
| **Cold storage (S3)** | `(daily_raw / 4 × cold_days) × $0.0125`, `cold_days = 365` |
| **CDN config egress** | `DAU × eff_cfg_bytes × $0.05`, `eff_cfg_bytes ≈ 2 KB` (304-dominated) |
| **KMS** | key rotation + envelope ops only (token signing done in-process with rotated keys) — low |
| **Redis sessions** | `peak_sessions × 300 B × $35/GB-mo` |

Two design choices keep several lines near-floor regardless of event volume:

- **Config egress scales with *users*, not events**, and is dominated by
  `304 Not Modified` because config is signed + cacheable + device-cached
  ([CDN config](../ARCHITECTURE.md#how-to-stay-lightweight)).
- **KMS is not called per token/proof.** Trust tokens are signed **in-process**
  with periodically rotated, HSM-released keys, and request proofs are verified
  against **cached public keys** — so KMS op volume is key-management traffic,
  not per-request traffic. (A naive "KMS sign per token" design would cost
  thousands of dollars/month at 100M MAU; kseal explicitly avoids it.)

---

## Good-Design Cost by Scale

Line items computed from the formulas (rounded). "Raw retention" is the **paid
add-on** path (full events hot 30d + cold 365d); the **default aggregates path**
is cheaper still because raw events are not stored
([raw events off by default](../ARCHITECTURE.md#store-compliance)).

| Line item | 10M MAU | 100M MAU | 300M MAU |
|---|---|---|---|
| Ingest bandwidth | ~$0 | ~$0 | ~$0 |
| Compute (Go workers) | $120 | $120 | $150 |
| Streaming (Kafka/Redpanda) | $300 | $305 | $303 |
| Hot storage (ClickHouse, 30d raw) | $1 | $8 | $25 |
| Cold storage (S3, 365d raw) | $2 | $17 | $51 |
| CDN config egress | $9 | $90 | $270 |
| KMS | $5 | $10 | $30 |
| Redis (trust sessions) | $30 | $70 | $100 |
| **Total (raw retention)** | **≈ $470/mo** | **≈ $620/mo** | **≈ $930/mo** |
| **Total (aggregates default)** | **≈ $460/mo** | **≈ $595/mo** | **≈ $850/mo** |

The headline: with the good design, **the data is almost free** — even at 300M
MAU the event-driven storage lines total well under $100/month. Cost is set by
**fixed floors** (streaming cluster, HA compute) and by **user-scaled** lines
(config egress, Redis), exactly as the architecture intends.

---

## Naive vs Good Comparison

Same rate card, naive knobs (`E=20, B=500`):

| Line item | 10M (naive) | 100M (naive) | 300M (naive) |
|---|---|---|---|
| Compute | $120 | $480 | $1,200 |
| Streaming | $302 | $322 | $568 |
| Hot storage (30d raw) | $17 | $169 | $506 |
| Cold storage (365d raw) | $34 | $342 | $1,027 |
| CDN config egress | $9 | $90 | $270 |
| KMS | $10 | $30 | $80 |
| Redis | $30 | $70 | $100 |
| **Total (naive)** | **≈ $520/mo** | **≈ $1,500/mo** | **≈ $3,750/mo** |

### Good vs naive, side by side

| Scale | Good (raw retention) | Naive | Blended multiple | Variable-cost multiple* |
|---|---|---|---|---|
| 10M MAU | ~$470 | ~$520 | 1.1× | ~3–4× |
| 100M MAU | ~$620 | ~$1,500 | 2.4× | ~6–8× |
| 300M MAU | ~$930 | ~$3,750 | 4.0× | ~10–15× |

\* *Variable-cost multiple* isolates the event-driven lines
(compute + streaming throughput + hot + cold), excluding fixed floors and
user-scaled lines.

**Interpretation.** The raw event-math gap is **20×**, but the *blended* infra
multiple is smaller (1.1×→4×) because fixed floors and user-scaled costs (config
egress, Redis, cluster minimums) dilute it. The gap **widens with scale** as
floors amortize: at 10M the two designs are nearly identical, but by 300M the
naive design is ~4× more expensive blended and ~10–15× on marginal event cost.
That **marginal** cost is what determines gross margin on the
[event-based pricing axis](../PROPOSAL.md#pricing-model-direction) — so the good
design is what makes 100M+-MAU pricing viable, precisely the
[Unit Economics](../PROPOSAL.md#unit-economics) claim.

---

## What Dominates Cost (Sensitivity)

Ranked by leverage on total cost:

1. **Events per user per day (`E`)** — linear on compute, streaming, and storage;
   the single biggest lever. Halving `E` nearly halves variable cost. This is why
   kseal has **no heartbeat** and is strictly event/risk-driven.
2. **Raw retention vs aggregates** — storing raw events (paid add-on) vs
   aggregates-by-default is the difference between paying for `monthly_raw` and
   paying for ~2% of it. Hence **raw is opt-in and priced separately**.
3. **Bytes per event (`B`)** — linear on storage and wire. Packed risk bits +
   coarse confidence + salted hashes keep `B` ≈ 250 instead of ≈ 500.
4. **Compression ratio** — every additional × on zstd/columnar compression is a
   direct discount on streaming + storage; shared dictionaries make small batches
   compress hard.
5. **Hot retention window** — hot storage cost is linear in `hot_days`; tiering to
   cold S3 after 30 days cuts the expensive line.
6. **Attestation strategy** — attest-on-sensitive-action + cached trust sessions
   keeps Play Integrity within the [10K/day quota](android-policy-review.md#play-integrity-api-quota-model)
   and keeps KMS/verifier load off the per-request path.

Lines that **do not** scale with events (and so set the floor at low volume):
streaming cluster minimum, HA compute minimum, CDN config egress (user-scaled),
and Redis sessions (user-scaled).

---

## Mapping to Cost-Control Rules

Each [cost-control rule](../PROPOSAL.md#unit-economics) maps to a specific line
above:

| Cost-control rule | Line(s) it protects |
|---|---|
| No heartbeat | Compute, streaming, storage (caps `E`) |
| No raw telemetry by default | Hot + cold storage (aggregates vs raw) |
| No attestation on every call | KMS, verifier compute, Play Integrity quota |
| CDN-served config | CDN egress (304-dominated, no origin hit) |
| Batch events | Compute, streaming (fewer, larger requests) |
| zstd dictionaries | Streaming + cold storage (4× compression) |
| Sampling | Compute + storage (drops low-severity volume) |
| Edge rejection | Compute (drop malformed/over-quota before downstream cost) |
| Hot/cold retention | Hot storage (30d) vs cold S3 (365d) |
| Raw data as a paid feature | Aligns the expensive line with the paying tenant |
| Local build transforms | Removes per-build cloud compute entirely (not in this data-plane model) |

---

## Implications for Pricing

The model validates the three [pricing axes](../PROPOSAL.md#pricing-model-direction):

- **MAU/MAD-based (primary).** User-scaled costs (config egress, Redis,
  attestation) track MAU, so MAU pricing covers the floor + per-user lines.
- **Event-based (usage).** Variable cost is dominated by `E × B`; an event
  component beyond an included tier directly recovers the marginal
  compute/streaming/storage cost — which is where the 10–15× design gap lives.
- **Retention-based (add-on).** Raw retention is the most volume-sensitive line;
  charging for raw + extended history aligns price with the tenant actually
  consuming that storage, keeping the base offer (aggregates + standard
  retention) cheap.

Because the good design keeps blended infra cost in the **hundreds of dollars per
month even at 300M MAU**, the dominant real cost at scale is **not raw infra** but
**HA/operational headroom and the paid raw-retention path** — which the pricing
model deliberately pushes onto the tenants who opt into it. See
[feature-parity-matrix.md](feature-parity-matrix.md#where-kseal-wins-matches-and-trails)
for how this "lightweight / lower operating cost" position compares to incumbents.
