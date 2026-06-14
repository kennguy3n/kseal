---
hide:
  - navigation
  - toc
---

<div class="kseal-hero" markdown>

# Ship apps attackers can't quietly break

**kseal** is a multi-plane mobile & desktop app-security platform: build-time
hardening, on-device RASP, and server-authoritative API attestation — operated
NoOps for thousands of SME tenants.

[Secure your app in 4 steps :material-arrow-right:](secure-your-app.md){ .md-button .md-button--primary }
[Read the architecture](ARCHITECTURE.md){ .md-button }

</div>

<div class="grid cards" markdown>

-   :material-hammer-wrench:{ .lg .middle } &nbsp; **Build-time hardening**

    ---

    Harden inside your own CI — no source upload, no per-build cloud compute.
    String/resource encryption, bytecode obfuscation, native posture
    verification, and a reproducible **build proof**.

    [:octicons-arrow-right-24: Android](docs/build-hardening-android.md) ·
    [iOS](docs/build-hardening-ios.md)

-   :material-shield-check:{ .lg .middle } &nbsp; **On-device RASP**

    ---

    Runtime self-protection: root/jailbreak, hook/debugger and tamper detection
    with a polymorphic, per-build posture so a bypass crafted for one release
    decays against the next.

    [:octicons-arrow-right-24: Desktop SDK](docs/desktop-sdk.md)

-   :material-server-network:{ .lg .middle } &nbsp; **API attestation & trust**

    ---

    Server-authoritative trust sessions bind each request to an attested,
    untampered app instance — so your backend can refuse traffic from
    compromised clients.

    [:octicons-arrow-right-24: Threat model](docs/threat-model.md)

-   :material-cloud-cog:{ .lg .middle } &nbsp; **NoOps operations**

    ---

    Multi-region, BYOK/CMK, on-prem, SIEM, signed kill-switch and canary
    rollout — run security for 5,000+ tenants without an ops team.

    [:octicons-arrow-right-24: Deployment](docs/deployment.md)

</div>

## A guided path to a more secure app

You don't need to be a security engineer. The **[Secure your app](secure-your-app.md)**
walkthrough takes you from zero to an attested, hardened release in four steps —
with sensible defaults at every turn and copy that explains *why* each control
matters.

<div class="grid cards kseal-steps" markdown>

-   **1 · Install the plugin**

    Add the Gradle or Xcode plugin. One line, off-the-shelf defaults that are
    safe to ship.

-   **2 · Harden the build**

    Encrypt strings, obfuscate bytecode, verify native mitigations — all inside
    your existing build.

-   **3 · Register the build proof**

    Publish a tamper-evident manifest of exactly what was hardened to the
    control plane.

-   **4 · Verify at runtime**

    The SDK attests the running app against its build proof, so your backend
    trusts only genuine instances.

</div>

[Start the walkthrough :material-arrow-right:](secure-your-app.md){ .md-button .md-button--primary }

## Find your way around

| If you want to… | Go to |
|---|---|
| Make an app more secure, fast | **[Secure your app](secure-your-app.md)** — the guided 4-step path |
| Understand the design | [Architecture overview](ARCHITECTURE.md) · [Design proposal](PROPOSAL.md) |
| Integrate build hardening | [Android (Gradle)](docs/build-hardening-android.md) · [iOS (Xcode)](docs/build-hardening-ios.md) |
| Operate the platform | [Deployment](docs/deployment.md) · [Multi-region](docs/multi-region.md) · [BYOK](docs/byok.md) · [SIEM](docs/siem-integration.md) |
| Produce compliance evidence | [MASVS mapping](docs/masvs-mapping.md) · [MASVS evidence report](docs/masvs-evidence.md) |
| Judge maturity honestly | [Feature parity matrix](docs/feature-parity-matrix.md) |

!!! info "Everything here is sourced from the repository"
    This site is assembled directly from the canonical Markdown in the
    [kseal repository](https://github.com/kennguy3n/kseal) — no doc body is
    duplicated, so the docs you read are exactly the docs that ship.
