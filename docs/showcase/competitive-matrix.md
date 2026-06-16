# Competitive positioning matrix

How kseal's demonstrated capabilities line up against top-tier players, viewed through the
lens of the **SME-at-scale, NoOps** segment (millions of MAU, no security team, no ops
budget). The point isn't that kseal beats every incumbent at the incumbent's specialty — it's
that kseal delivers the **whole job** in one product, zero-config, operable by one engineer.

Legend: **●** built-in / zero-config · **◑** present but requires config/analyst/integration ·
**○** not the product / DIY.

| Capability (with showcase evidence) | kseal | Approov | Guardsquare / Appdome / Promon | Castle / Arkose | Play Integrity / App Attest |
|---|:--:|:--:|:--:|:--:|:--:|
| Server-authoritative trust token bound to instance+build+risk+nonce+policy (`18`) | ● | ◑ | ○ | ○ | ○ (raw attestation only) |
| Fuse device signals **and** platform attestation server-side, with correct bit semantics (`15`) | ● | ◑ | ○ | ○ | ○ |
| Global decision stream + one-click risk triage in-product (`15`,`16`) | ● | ◑ | ○ | ◑ | ○ |
| **Fleet/population coordinated-abuse detection, zero-config** (`10`) | ● | ○ | ○ | ◑ (analyst-tuned) | ○ |
| Per-(build, region) cohort baselines + volume-velocity, O(1)/event (`10`) | ● | ○ | ○ | ◑ | ○ |
| Signed, client-verifiable remote kill switch (`05`,`06`) | ● | ◑ | ◑ | ○ | ○ |
| Hash-chained, **console-verified** audit trail (`08`,`13`) | ● | ○ | ○ | ◑ | ○ |
| Signed webhooks + SIEM with **named** signals & sealed secrets (`17`,`19`,`07`) | ● | ○ | ○ | ◑ | ○ |
| OWASP-MASVS coverage **derived from build proof** (`12`) | ● | ○ | ◑ (hardening reports) | ○ | ○ |
| In-product data-processing / retention registry (`11`) | ● | ○ | ○ | ○ | ○ |
| Canary rollout of trust policy + auto-rollback guardrail (`14`) | ● | ○ | ○ | ◑ | ○ |
| **Operable by one engineer, zero analysts/ops** | ● | ◑ | ◑ | ○ | ◑ |
| **One platform for the whole job** (attestation → fleet → response → compliance) | ● | ○ | ○ | ○ | ○ |

## Reading the matrix

- **Approov** is a credible server-side attestation peer, but it leaves fleet analytics, SIEM
  correlation, compliance evidence and staged policy rollout to the customer.
- **Guardsquare / Appdome / Promon** are app-hardening leaders (obfuscation, RASP). They make
  the app harder to attack; they are not the server-side trust-decision, fleet-analytics,
  response and compliance suite.
- **Castle / Arkose** are strong at population/behavioral abuse — genuinely a peer (or better)
  on that single axis — but they are account-abuse platforms that expect analyst tuning, not
  mobile-attestation + integrity + compliance suites.
- **Play Integrity / App Attest** are raw platform signals — an *input* to kseal, not a
  product that decides, detects fleets, responds, or proves compliance.

## How to read these marks honestly

The kseal column is grounded in this repository: each **●** above corresponds to code that
ships and a test that gates it (see [Evidence & back-testing](evidence-and-backtesting.md)
for the suite and the device hot-path numbers). The competitor columns reflect **publicly
described product positioning**, not a hands-on bake-off — vendor offerings change, and an
SME should revalidate against current docs before a procurement decision. The honest claim
is narrow and defensible: *not that kseal out-obfuscates Guardsquare or out-detects Arkose
on their home turf*, but that it delivers the **whole row** — attestation → fleet analytics
→ response → compliance — zero-config and operable by one engineer.

## The economics axis the matrix doesn't show

The capability marks say nothing about *what it costs to operate*, which for an SME is the
whole game. kseal's design choices make the whole row affordable, and the numbers come from
the bottom-up [cost model](../cost-model.md), not a slide:

| | kseal | Typical "assemble 3 products + a pipeline" path |
|---|---|---|
| Blended data-plane infra at 100M MAU | **≈ $585/mo** (aggregates default) | Multiple per-seat/per-MAU contracts + a data lake + analyst headcount |
| Per-token/proof KMS cost | **≈ $0** (in-process signing, cached-key verify; KMS scales with ~5k tenants, not MAU) | Often per-call, thousands/mo at scale if naive |
| People to operate | **1 engineer, 0 analysts** | Security team + ops + data engineering |

That economics gap is the point: each incumbent owns one column well, but the SME needs the
whole row *and* can't staff or fund four integrations to get it.

## The SME thesis in one line

> Each incumbent owns one column well. The SME needs the **whole row** — and can't afford to
> hire the team required to wire four products together. kseal's wedge is delivering the
> whole row, zero-config, at SME-at-scale economics (O(1)/event, bounded memory, aggregates-
> only, in-process).
