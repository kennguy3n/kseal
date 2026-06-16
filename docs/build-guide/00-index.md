# How to build a continuous app-trust platform

> A build-along series. The [showcase](../showcase/00-showcase-index.md) shows kseal *doing
> the job*; this series shows **how it's built** — the architecture, the trust protocol, the
> scale and privacy engineering, and the business decision behind every choice. It's written
> for two readers at once: an **engineer** who wants to rebuild a system like this, and a
> **product/founder** who wants to understand *why* each call was made versus the incumbents.

Every chapter has the same shape so both readers can follow the same thread:

- **The decision** — the question on the table, in plain language.
- **The options** — what the incumbents do, and the honest trade-offs.
- **What we built** — the concrete mechanism, with the real files in this repo.
- **The business read** — what the choice buys (or costs) commercially.

This is not a rewrite of the [ARCHITECTURE.md](../../ARCHITECTURE.md) reference — it's the
*narrative* of how you'd arrive at that architecture from first principles, and how you'd
defend each decision in a room with a CFO and a CISO.

---

## The one-sentence thesis

> **Pure client-side protection is always bypassable, so move the trust *decision* to a
> server, bind every protected request to it, and make the whole thing operable by one
> engineer at SME economics.**

Everything in the series is a consequence of that sentence.

---

## The chapters

| # | Chapter | The core decision | Primary reader |
|---|---|---|---|
| 1 | [The thesis & the business case](01-thesis-and-business-case.md) | Why server-authoritative trust, and who pays for it | Product |
| 2 | [Architecture — the four planes](02-architecture-four-planes.md) | How to split the system so it scales and stays cheap | Both |
| 3 | [The device plane — RASP + a Rust trust core](03-device-plane-rasp-and-rust-core.md) | What runs on the phone, and what deliberately doesn't | Engineer |
| 4 | [The trust protocol — attestation, tokens & request proofs](04-trust-protocol-attestation-and-proofs.md) | The cryptographic contract that can't be forged | Engineer |
| 5 | [The data plane — ingest, fleet anomaly & risk fusion at scale](05-data-plane-ingest-fleet-and-risk.md) | How to detect coordinated abuse at O(1)/event | Both |
| 6 | [The control plane — registry, policy, audit & response](06-control-plane-registry-policy-audit.md) | The source of truth, and the evidence trail | Both |
| 7 | [Privacy & compliance as features](07-privacy-and-compliance.md) | Turning data-minimization and MASVS into product, not paperwork | Both |
| 8 | [Cost, scale & NoOps economics](08-cost-scale-and-noops-economics.md) | Making the unit economics work at 100M MAU | Product |
| 9 | [Business scenarios — making the call vs the incumbents](09-business-scenarios-and-tradeoffs.md) | Five decisions, five rooms, five trade-offs | Product |

---

## How to use it

- **Building it?** Read 2 → 3 → 4 → 5 → 6 in order; each names the exact crates/packages in
  this repo so you can read the real implementation alongside the narrative.
- **Deciding whether to build/buy it?** Read 1 → 8 → 9; they're about money, staffing and
  positioning, with the engineering as supporting evidence.
- **Want proof the claims are real?** Every "what we built" cites code that ships and tests
  that gate it — cross-referenced from [Evidence & back-testing](../showcase/evidence-and-backtesting.md).

> A note on framing: this series describes the platform **as it stands today** — the current
> codebase, treated as the latest and complete system. It is a guide to building *a* platform
> like this, not a changelog of how this one grew.
