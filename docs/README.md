# docs

Additional documentation, threat models, and MASVS mapping.

Complements the top-level [README](../README.md), [PROPOSAL](../PROPOSAL.md), [ARCHITECTURE](../ARCHITECTURE.md), and [PROGRESS](../PROGRESS.md). Expected contents:

- **Threat models** — per-vertical (fintech, gaming, health, media) attacker profiles and STRIDE analysis.
- **MASVS mapping** — control-by-control mapping to [OWASP MASVS](https://mas.owasp.org/MASVS/) categories and MASTG test procedures.
- **Cost model** — ingest/storage/retention math at 10M / 100M / 300M MAU.
- **Feature parity matrix** — comparison vs AppSealing/DoveRunner and other incumbents.
- **Runbooks / ADRs** — operational guides and architecture decision records.
  - [Virtualization-tier decision](virtualization-tier-decision.md) — Phase 5.3 spike, measured perf/size, and the GO/NO-GO recommendation.

## Narrative series

Two long-form, blog-style series complement the reference docs above:

- **[Capability showcase](showcase/00-showcase-index.md)** — kseal *doing the job*, told
  through five companies, with live console screenshots and a
  [measured evidence / back-testing](showcase/evidence-and-backtesting.md) appendix.
- **[How to build a continuous app-trust platform](build-guide/00-index.md)** — a build-along
  series for engineers *and* product readers: the architecture, the trust protocol, the scale
  and privacy engineering, and the business decision behind each choice versus the incumbents.
