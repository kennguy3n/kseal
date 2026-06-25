# docs

Reference documentation, threat models, compliance mappings, and operational guides for kseal.

Start with the top-level [README](../README.md) and [ARCHITECTURE](../ARCHITECTURE.md). Everything here is grounded in a single canonical reference deployment — **Meridian Pay** — whose attestation payloads, risk-scored events, and control-plane artifacts are committed as JSON fixtures under [`reference/fixtures/`](reference/fixtures/), so every figure and example across the docs traces back to the same dataset.

## Reference (source of truth)

- **[Benchmarks](reference/benchmarks.md)** — every performance, memory, and binary-size figure quoted across the docs, traced back to the test that produces it.
- **[Risk signals](reference/risk-signals.md)** — the authoritative device→server signal mapping, weights, thresholds, and scoring formula, with the five worked Meridian scenarios.
- **[Voice & style](reference/voice-and-style.md)** — the documentation style guide.
- **[Fixtures](reference/fixtures/)** — the committed Meridian Pay dataset every doc cites.

## Guides and references

- **Threat model** — [threat-model.md](threat-model.md): attacker profiles and STRIDE analysis.
- **Authorization** — [authz-hardening.md](authz-hardening.md): current per-procedure policy, scope, platform-admin, and device-credential model.
- **Compliance** — [MASVS mapping](masvs-mapping.md), [MASVS evidence](masvs-evidence.md), and [MASTG procedures](mastg-procedures.md), plus the [Android](android-policy-review.md) and [iOS](ios-app-review.md) store-policy reviews.
- **Economics** — [cost model](cost-model.md): ingest/storage/retention math at 10M / 100M / 300M MAU.
- **Competitive** — [feature parity matrix](feature-parity-matrix.md) versus AppSealing/DoveRunner and other incumbents.
- **Operations** — deployment ([cloud](deployment.md), [on-prem](deployment-onprem.md), [private link](deployment-private-link.md), [disaster recovery](deployment-disaster-recovery.md)), [multi-region](multi-region.md), [kill switch](kill-switch.md), [canary rollout](canary-rollout.md), and the [CLI](cli.md).

## Narrative series

Two long-form, blog-style series complement the reference docs above:

- **[Capability showcase](showcase/00-showcase-index.md)** — kseal *doing the job* for Meridian Pay, grounded in committed [reference fixtures](reference/fixtures/README.md) with a [measured evidence / back-testing](showcase/evidence-and-backtesting.md) appendix.
- **[How to build a continuous app-trust platform](build-guide/00-index.md)** — a build-along series for engineers *and* product readers: the architecture, the trust protocol, the scale and privacy engineering, and the business decision behind each choice versus the incumbents.
