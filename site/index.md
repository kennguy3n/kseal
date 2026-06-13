# kseal documentation

**kseal** is a multi-tenant mobile & desktop app-shielding platform: on-device
RASP, server-authoritative API attestation / trust sessions, build-time
hardening, and the operational surface (multi-region, BYOK/CMK, on-prem, SIEM,
NoOps CLI, MSSP console) to run it for thousands of SME tenants.

This site organizes the repository's existing documentation into one navigable
place. Every page is sourced directly from the canonical Markdown in the repo —
nothing here is duplicated.

## Start here

- **New to kseal?** Read the [project overview](project-overview.md), then the
  [architecture](ARCHITECTURE.md).
- **Integrating an app?** See the SDK guides for
  [Android](docs/build-hardening-android.md), [iOS](docs/build-hardening-ios.md),
  and [desktop](docs/desktop-sdk.md) — and the runnable
  [`examples/`](https://github.com/kennguy3n/kseal/tree/main/examples) quickstarts.
- **Running the platform?** See [deployment](docs/deployment.md),
  [multi-region](docs/multi-region.md), [BYOK](docs/byok.md), and
  [SIEM integration](docs/siem-integration.md).
- **Evaluating maturity?** See the
  [feature parity matrix](docs/feature-parity-matrix.md).

## Sections

| Section | Contents |
|---|---|
| **Getting started** | Project overview, threat model |
| **Architecture** | Four-plane architecture, design proposal |
| **SDK guides** | Android / iOS / desktop hardening + integration, CLI |
| **Server & ops** | Deployment, multi-region, BYOK, on-prem, SIEM, policy packs, MSSP console, cost model |
| **Compliance** | MASVS mapping & evidence, app-store review notes |
| **Parity matrix** | Honest capability comparison vs. incumbents |
