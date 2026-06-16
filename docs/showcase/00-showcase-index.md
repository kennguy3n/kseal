# kseal in the real world — a capability showcase

> A blog-series showcase built entirely from **live console screenshots** of a running
> kseal stack (server + console), driven with real attestations, real trust decisions,
> real telemetry and real control-plane mutations. Nothing here is a mockup. Every number,
> hash, timestamp and chart was produced by the product doing its job.

kseal is a **server-authoritative mobile app-protection and attestation platform** for the
SME segment: teams with millions of installs but **no dedicated security analysts and no ops
budget**. The thesis of this showcase is simple — the capabilities that the top-tier players
(Approov, Guardsquare, Appdome, Promon, Castle, Arkose) charge enterprise money and require
enterprise staffing for, kseal delivers **zero-config, in-product, and operable by one
engineer**.

Rather than walk the feature list, we follow five companies doing their actual jobs.

---

## The cast — personas, companies & jobs-to-be-done

| # | Company | Persona | Job to be done (JTBD) | kseal capability | Screenshot |
|---|---------|---------|------------------------|------------------|------------|
| 1 | **NovaPay** (fintech wallet) | Mobile security lead | "Only let *genuine, untampered* app installs move money — and prove every decision to my SOC." | Server-authoritative trust token; risk fusion; global event stream; signed webhooks; SIEM streaming | `15`, `16`, `17`, `18`, `19` |
| 2 | **FitPulse** (consumer fitness, NoOps) | Solo founder / staff eng | "I have no analysts. Tell me automatically when a build is under coordinated attack." | **Fleet Anomaly Guard** — zero-config per-cohort baselines + auto step-up | `10` |
| 3 | **GameForge** (mobile gaming) | Trust & Safety / SOC | "When a cheat/abuse wave hits, kill it in seconds and have a tamper-evident record." | Signed remote kill switch; hash-chained audit trail; SIEM | `01`, `02`, `03`, `04`, `05`, `06`, `07`, `08`, `09` |
| 4 | **MediToken** (regulated health) | Compliance / AppSec owner | "Prove OWASP-MASVS coverage and document exactly what data we process." | MASVS evidence from build-proof; data-processing registry; audit | `11`, `12`, `13` |
| 5 | **ShopSwift** (e-commerce) | Release engineer | "Ship a policy change to a slice of traffic with an automatic safety net." | Canary rollout with block-rate guardrail + auto-rollback | `14` |

Screenshot numbers refer to files in [`screenshots/`](screenshots/).

---

## Why these jobs are hard for the SME segment

The incumbent tools are built for organizations that **already have** a security team:

- **Approov** does excellent runtime attestation, but population-level abuse analytics and
  SIEM correlation are an exercise left to *your* analysts and *your* data pipeline.
- **Guardsquare / Appdome / Promon** are app-hardening powerhouses (obfuscation, RASP), but
  the *server-side trust decision*, *fleet analytics*, *staged rollout* and *compliance
  evidence* are not their job — you assemble those yourself.
- **Castle / Arkose** bring strong population/behavioral abuse detection, but they are
  account-abuse platforms, not mobile attestation + app-integrity + compliance suites, and
  they expect analyst tuning.

The SME doesn't have the people to integrate four products and a data lake. kseal's bet is
**one platform, zero-config defaults, one-engineer operability** — without giving up the
depth that makes the incumbents credible.

---

## What "for real" means here

Everything in the series was generated against a live stack:

- **5 tenants** (NovaPay, FitPulse, GameForge, MediToken, ShopSwift), each with real apps,
  builds, policies and API keys.
- **Tens of thousands of telemetry events** and **thousands of trust sessions** driven
  through the real `TrustService.VerifyAttestation` RPC with signed Play-Integrity-style
  tokens (dev attestation key), producing genuine TRUSTED / MEDIUM / HIGH / CRITICAL bands.
- A **coordinated root surge** of 320+ attestations against FitPulse's `fitpulse-3.9` build
  in a 5-minute window — caught live by Fleet Anomaly Guard (screenshot `10`).
- Real control-plane mutations: a **signed kill switch** armed and disabled (GameForge), a
  **25% canary** staged (ShopSwift), **data-processing records** registered (MediToken) —
  each producing **hash-chained audit entries** that the console independently verifies.

Two real platform defects were found and fixed **because** we insisted on driving the real
product instead of mocking it (see [`defects-found.md`](defects-found.md)).

And because "works in a screenshot" isn't proof, every chapter is backed by **measured,
reproducible numbers** — device hot-path latency (nanoseconds to microseconds), the
Go + Rust test suites that gate each capability, the back-tested abuse surge, and the
bottom-up cost model. They live in one place: [Evidence & back-testing](evidence-and-backtesting.md).
It all regenerates from a clean checkout with `make test` and `cargo bench`.

---

## The series

1. [NovaPay — proving every payment comes from a genuine app](01-novapay-fintech.md)
2. [FitPulse — the NoOps founder who gets an analyst for free](02-fitpulse-noops-sme.md)
3. [GameForge — killing an abuse wave in seconds, with receipts](03-gameforge-incident-response.md)
4. [MediToken — turning a build into compliance evidence](04-meditoken-compliance.md)
5. [ShopSwift — shipping a policy change with a seatbelt](05-shopswift-release-engineer.md)

Appendices:
- [Evidence & back-testing](evidence-and-backtesting.md) — the measured numbers behind every chapter
- [Competitive positioning matrix](competitive-matrix.md)
- [Defects found & fixed while making this showcase](defects-found.md)

---

## Want to build one?

This showcase shows kseal *doing the job*. If you want to understand **how it's built** —
the architecture, the trust protocol, the scale and privacy engineering, and the
business decisions behind each choice versus the incumbents — see the companion
[**How to build a continuous app-trust platform**](../build-guide/00-index.md) series.
It's written so a technical *and* a product reader can follow the same thread from "why"
to "how," and rebuild a system like this.
