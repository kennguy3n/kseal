# Chapter 8 — Cost, scale & NoOps economics

> **The decision:** A capability the SME can't afford isn't a capability. How do you keep the
> infrastructure bill near-flat as MAU grows from 10M to 300M — and operable by one engineer?

This chapter is the one a product or finance reader should read most closely. The
[full cost model](../cost-model.md) has the formulas; here's the reasoning.

---

## The spine: how much data does this actually move?

Daily raw ingest is what everything else hangs off. With the **good-design** knobs (DAU/MAU
ratio `r = 0.30`, `E = 2` events/DAU/day, `B = 250` raw bytes/event):

| MAU | DAU | daily events | daily raw | peak eps |
|---|---|---|---|---|
| 10M | 3M | 6M | 1.5 GB/day | ~210 |
| 100M | 30M | 60M | 15 GB/day | ~2,100 |
| 300M | 90M | 180M | 45 GB/day | ~6,250 |

The striking thing is how *low* the event rate is — even at 100M MAU it's only ~2k events/s at
peak. A **naive** chatty design (`E = 20`, `B = 500`) produces ~300 GB/day at 100M — a **20×**
raw-ingest gap. The design choice that creates that gap: **sparse, risk-driven, batched,
compressed telemetry** instead of a fixed heartbeat with raw payloads
([Chapter 3](03-device-plane-rasp-and-rust-core.md)).

---

## The blended bill

Run the per-resource formulas at the three scales (aggregates-default path; representative
public-cloud rates):

| Scale | Blended data-plane infra |
|---|---|
| 10M MAU | **≈ $465/mo** |
| 100M MAU | **≈ $585/mo** |
| 300M MAU | **≈ $945/mo** |

The bill barely moves from 10M to 100M MAU. That's not luck; it's three deliberate decisions:

### 1. Never call KMS per token/proof

Trust tokens are signed **in-process** with periodically rotated, HSM-released keys; request
proofs verify against **cached public keys**. So KMS op volume is *key-management* traffic, not
*per-request* traffic. A naive "KMS sign per token" design would cost **thousands of
dollars/month** at 100M MAU; here KMS scales with the **tenant** count (~5,000 SME tenants),
not MAU — so the KMS line is ~$10/mo at 100M and *identical* for the good and naive designs.
This is a direct consequence of the control/data-plane split in
[Chapter 2](02-architecture-four-planes.md) and the in-process signing in
[Chapter 4](04-trust-protocol-attestation-and-proofs.md).

### 2. Config egress scales with *users*, not events — and is `304`-dominated

Config is signed + cacheable + device-cached, so most fetches return `304 Not Modified`. CDN
egress tracks user count, not event volume, and stays small (~$90/mo at 100M).

### 3. Compute and cluster floors dominate, not the data

Because good-design ingest at 100M is only ~2k eps, you're paying for HA floors (a 4-vCPU
worker floor, a $300 streaming-cluster floor), not for data volume. The data itself is cheap:
zstd ~4× on the wire, ClickHouse ~8× columnar on disk, raw events **off by default**
(aggregates path is cheaper still).

> The compression cost is microseconds, not a tax: `batch_and_compress_10` ≈ 33 µs on device,
> `decompress_batch_10` ≈ 16 µs on the server ([Chapter 3](03-device-plane-rasp-and-rust-core.md)).

---

## NoOps is an economic property, not just a UX one

"Operable by one engineer" is on this page deliberately — **people are the biggest line item**
the cost model *doesn't* show. The platform removes the roles the incumbent path requires:

| Role the incumbent path needs | How kseal removes it |
|---|---|
| Security analyst (tune abuse rules) | Fleet baselines are *learned*, zero-config ([Chapter 5](05-data-plane-ingest-fleet-and-risk.md)) |
| Data engineer (build the pipeline) | Signed webhooks + minimized SIEM stream out of the box ([NovaPay](../showcase/01-novapay-fintech.md)) |
| Compliance analyst (gather evidence) | MASVS + data-processing derived from build proof ([Chapter 7](07-privacy-and-compliance.md)) |
| Release/SRE (safe policy rollout) | Canary + auto-rollback built into the trust layer ([Chapter 6](06-control-plane-registry-policy-audit.md)) |

The "heavy parts off by default, fail-closed" posture (in-process broker + in-memory store
until `KSEAL_BROKER` / `KSEAL_ANALYTICS` are set) is the same idea: a small tenant pays for —
and operates — almost nothing; the architecture *is* the pricing ladder.

---

## The business read

- **Near-flat infra cost from 10M→100M MAU is the unlock** for SME-at-scale pricing. You can
  price per-MAU on a thin, predictable cost base instead of passing through a volatile data
  bill.
- **The biggest savings are in headcount you never hire**, not in the cloud bill. The cost
  model shows the infra is cents; the real story you sell is "you don't need the analyst, the
  data engineer, or the integration project."
- **Off-by-default heavy components are how one product serves both a 1M-MAU startup and a
  300M-MAU scaler** without two codebases — and how a single engineer keeps it running.

Next: [Chapter 9 — Business scenarios](09-business-scenarios-and-tradeoffs.md), where these
decisions get made in five concrete rooms.
