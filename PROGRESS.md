# kseal — Development Progress

This document tracks delivery against the six-phase roadmap. Status values: **NOT STARTED**, **IN PROGRESS**, **DONE**.

## Phase Summary

| Phase | Theme | Duration | Status |
|---|---|---|---|
| [Phase 0](#phase-0-research--threat-model-6-8-weeks) | Research & Threat Model | 6–8 weeks | **DONE \| 100%** |
| [Phase 1](#phase-1-api-trust-product-3-4-months) | API Trust Product | 3–4 months | **DONE \| 100%** |
| [Phase 2](#phase-2-runtime-protection-4-6-months) | Runtime Protection | 4–6 months | **DONE \| 100%** |
| [Phase 3](#phase-3-build-time-hardening-6-9-months) | Build-Time Hardening | 6–9 months | **DONE \| 100%** |
| [Phase 4](#phase-4-enterprise-scale-9-12-months) | Enterprise Scale | 9–12 months | **DONE \| 100%** |
| [Phase 5](#phase-5-desktop-6-months-after-mobile-maturity) | Desktop | 6+ months post-mobile | **DONE \| 100%** |

---

## Phase 0: Research & Threat Model (6-8 weeks)

**Status: DONE | 100%**

Validate the threat model, standards mapping, platform constraints, and cost model before writing production code.

### Deliverables

| Deliverable | Status | Assignee | Notes |
|---|---|---|---|
| Threat model by vertical (fintech, gaming, health, media) | DONE | | `docs/threat-model.md` — STRIDE-style per-vertical attacker profiles |
| MASVS mapping | DONE | | `docs/masvs-mapping.md` — controls mapped to MASVS-STORAGE/CRYPTO/AUTH/NETWORK/PLATFORM/CODE/RESILIENCE/PRIVACY |
| iOS App Review safety review | DONE | | `docs/ios-app-review.md` — confirms public APIs only; App Attest/DeviceCheck |
| Android policy review | DONE | | `docs/android-policy-review.md` — Play policy + Play Integrity quota model |
| AppSealing / DoveRunner feature parity matrix | DONE | | `docs/feature-parity-matrix.md` — feature-by-feature comparison + gaps |
| SDK performance prototype | DONE | | `sdk/rust-core/kseal-core/benches/core_benches.rs` — Criterion benches for init/proof/compress |
| Attestation prototype | DONE | | `server/data-plane/attestation/{play_integrity,app_attest}.go` — end-to-end verify, proven by `tests/e2e_trust_flow_test.go` |
| Cost model at 10M / 100M / 300M MAU | DONE | | `docs/cost-model.md` — ingest, storage, compression, retention math |

### Exit criteria

| Criterion | Status | Notes |
|---|---|---|
| App startup overhead measured (< 40 ms p95) | DONE | `bench_core_init` in the Rust core benches measures the init budget |
| No private iOS API dependency confirmed | DONE | `docs/ios-app-review.md` static + dynamic review |
| Trust session flow proven end-to-end | DONE | Challenge → attest → token → signed proof, exercised by `tests/e2e_trust_flow_test.go` |
| Basic dashboard works | DONE | React/Vite console under `web/console`; overview backed by `QueryService` (`tests/e2e_query_overview_test.go`) |

---

## Phase 1: API Trust Product (3-4 months)

**Status: DONE | 100%**

**Milestone:** Protect APIs from fake clients and repackaged apps.

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Android SDK | DONE | | Kotlin SDK under `sdk/android` with probes + lifecycle integration |
| iOS SDK | DONE | | Swift SDK under `sdk/ios` with App Attest hooks |
| Rust trust core | DONE | | `sdk/rust-core/kseal-core` — policy eval, normalization, crypto formats, zstd compression |
| Play Integrity verifier | DONE | | `server/data-plane/attestation/play_integrity.go` — server-side verify + caching |
| App Attest verifier | DONE | | `server/data-plane/attestation/app_attest.go` — server-side attestation verify |
| Signed request proof | DONE | | `server/shared/crypto` `RequestProofPreimage` + HMAC; validated by `tests/e2e_trust_flow_test.go` |
| Trust session tokens | DONE | | `server/data-plane/trust` — short-lived tokens bound to instance+build+risk+nonce+policy |
| Config service | DONE | | `server/data-plane/config` — Ed25519-signed config; `tests/e2e_config_test.go` |
| Minimal dashboard | DONE | | React/Vite console under `web/console` backed by `QueryService` |
| Tenant / app / build registry | DONE | | `server/control-plane/registry` — control-plane source of truth |
| Webhooks | DONE | | `server/data-plane/webhook` — HMAC-signed fan-out with retries; `tests/e2e_webhook_test.go` |

---

## Phase 2: Runtime Protection (4-6 months)

**Status: DONE | 100%**

> **Default response order = `observe → step-up → block` (block only after simulation).**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Root / jailbreak / emulator / simulator detection | DONE | | `RootDetector`/`EmulatorDetector` (Android), `JailbreakDetector`/`SimulatorDetector` (iOS) |
| Debugger / hook detection | DONE | | `DebuggerDetector`/`HookDetector` on both platforms (ptrace/sysctl + Frida/Xposed) |
| App integrity | DONE | | `IntegrityChecker` on both platforms (repackaging/resigning detection) |
| Network MITM risk | DONE | | `NetworkRiskDetector` on both platforms (proxy/CA/pinning checks) |
| Local risk engine | DONE | | `sdk/rust-core/kseal-core/src/risk_engine.rs` — signal fusion in the Rust core |
| Policy simulator | DONE | | `server/data-plane/simulator` — replay traffic vs candidate policy |
| False-positive guardrails | DONE | | `server/data-plane/guardrails` — auto-detect anomalous block rates |
| SIEM integration | DONE | | `server/data-plane/siem` — per-tenant export to Splunk HEC / Microsoft Sentinel (DCR) / Elastic (ECS); backpressured, batched, at-least-once with idempotency keys + per-tenant circuit breaker; privacy allow-list (no PII); connector templates under `server/data-plane/siem/templates` |

---

## Phase 3: Build-Time Hardening (6-9 months)

**Status: DONE | 100%**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Gradle plugin | DONE | | `plugins/gradle` — `io.kseal.android.harden`, R8-aware; all tasks incremental + cacheable + config-cache compatible; Gradle TestKit functional tests |
| Xcode plugin | DONE | | `plugins/xcode` — XCFramework build + SwiftPM build-tool plugin + `kseal-harden` CLI; public-APIs-only (App Store safe) |
| Android obfuscation / resource / string encryption | DONE | | AES-256-GCM string/resource sealing + ASM debug-metadata stripping, R8 mapping-file aware |
| iOS string / symbol hardening | DONE | | Seed-XOR string hardening + `strip`/`nm`/`otool` symbol stripping + metadata stripping |
| Native library hardening | DONE | | Android `.so` CFI/MTE/BTI/PAC posture verified per-arch by `ElfInspector` and recorded in the build proof (unsupported toolchains reported, not skipped); iOS Mach-O section-hash + load-command integrity baked into the manifest via `kseal-harden integrity` |
| Per-build polymorphism | DONE | | Per-build HKDF-SHA256 polymorphism seed in both plugins (randomizes keys/structure per build) |
| Build proof | DONE | | `kseal.build-proof/v1` manifest (build hash + tool versions + seed digest), identical schema across Android/iOS; registered via `RegistryService.CreateBuild` with offline fallback |
| CI release gate | DONE | | `.github/workflows/release-gate.yml` — proto-drift, buf-breaking, build + unit/integration tests, container build + image scan; blocks release on failure |
| MASVS evidence report | DONE | | `tools/masvs-report` — zero-dependency Go CLI parsing both plugin manifest schemas + `docs/masvs-mapping.md` to emit per-release MASVS evidence (Markdown + JSON) from real build-proof data; optional Gradle/Xcode post-hardening task; `docs/masvs-evidence.md` |

---

## Phase 4: Enterprise Scale (9-12 months)

**Status: DONE | 100%**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Production data plane (Kafka/ClickHouse/OTLP) | DONE | | Production telemetry backends behind the existing `Broker`/`AnalyticsStore`/`EventSink` interfaces: Kafka/Redpanda broker (`broker_kafka.go` — at-least-once, tenant-partitioned, idempotent producer + load-shedding) and ClickHouse store (`store_clickhouse.go` — `ReplacingMergeTree` → effectively-once, `tenant_id`-leading `ORDER BY` isolation, monthly partitions + TTL/retention) + real OTLP spans/metrics on ingest/query/attestation hot paths. Selected via `KSEAL_BROKER`/`KSEAL_ANALYTICS` (default `memory`, fail-closed on misconfig); `QueryService` shapes + default behavior unchanged. Compose `dataplane` profile (Redpanda + ClickHouse) + additive Helm/Terraform (MSK Serverless, ClickHouse PrivateLink), testcontainers integration suite; `docs/data-plane-scale.md` |
| Multi-region data plane | DONE | | Terraform `multi-region` (regional Postgres primary + cross-region replica + analytics object store), `analytics-replication` (CRR fan-out), `global-routing` (latency/geo routing + health checks + per-tenant region-pin), `envs/multi-region` root (1→N regions from one config); region-scoped Helm values; `docs/multi-region.md`. All modules `terraform validate`-clean |
| Dedicated tenant tiers | DONE | | Enterprise/Regulated isolation via HKDF per-tenant key domain in the compliance backend (dedicated sealer/registry path), gated default-off; `docs/dedicated-tiers.md` |
| Audit trail + data-processing registry | DONE | | `ComplianceService` (`proto/kseal/v1/compliance_service.proto`, `server/control-plane/compliance`) — hash-chained, tamper-evident, tenant-scoped append-only audit log with `VerifyAuditChain`, plus a machine-readable data-processing registry; all RPCs require an API key and filter on the caller's tenant; `docs/audit-trail.md` |
| Signed kill switch | DONE | | Ed25519-signed remote disable/enable with monotonic anti-rollback version (serialized per scope via `pg_advisory_xact_lock`), delivered over the signed-config channel; forged/stale commands are no-ops; `docs/kill-switch.md` |
| Canary rollout + auto-rollback | DONE | | Deterministic tenant/app/instance bucketing with guardrail-driven auto-rollback to last-known-good; lock-free hot path; `docs/canary-rollout.md` |
| Fleet Anomaly Guard | DONE | | Population-level abuse detection (`server/data-plane/fleet`): per-`(tenant, app, build, region)` cohort baselines with two detectors — per-signal surge over a learned EWMA baseline AND volume-velocity spike (catches a coordinated flood of individually-clean clients). On a surge a server-derived `FLEET_ANOMALY` bit is fused into newly joining clients (graduated step-up, not a hard block). O(1)/event, sharded LRU-bounded memory, in-process/per-replica; surfaced via `kseal_fleet_anomaly_active{tenant,app,build,region}`, OTel span attrs, and the console Overview *Fleet anomalies* panel. Flag-gated (`fleet_anomaly`), default off; `docs/fleet-anomaly.md` |
| Risk-bit contract (wire ↔ server) | DONE | | Single source-of-truth `risk.FromWire` translation from the device/wire `RiskBitset` layout (Rust core, bits 0..15) into the server risk-bit layout (bits 0..10), applied at every device→server boundary (trust attestation + telemetry ingest) **before** fusion/scoring — fixes the latent dual-namespace foot-gun (e.g. wire `DEBUGGER` bit 4 vs server `APP_TAMPER` bit 4). Pinned on both ends by contract tests (Go `wire_contract_test.go`, Rust `bit_positions_are_stable`); `docs/risk-bit-contract.md` |
| Compliance NoOps tooling | DONE | | iOS privacy-manifest generator (`tools/privacy-manifest`), Google Data-Safety helper (`tools/datasafety`), MASTG procedure runner (`tools/mastg`), and `kseal` CLI compliance commands — driven by the SDK data contract, golden-file tested; `docs/privacy-manifest.md`, `docs/data-safety.md`, `docs/mastg-procedures.md` |
| Customer-managed keys (CMK) | DONE | | `server/shared/crypto` `TenantSealer` seam: platform-KEK default + per-tenant KMS-wrapped DEK (`CMKKeyManager`), self-describing `KSC1` envelope, fail-closed on KMS error and disabled-CMK open (`ErrCMKDisabled`); gated by `KSEAL_CMK_KMS_URI` (default off); `docs/byok.md` |
| Private link | DONE | | `deploy/terraform/modules/private-link` — private connectivity / private endpoints for regulated tenants, no public ingress; example tfvars; `docs/deployment-private-link.md` |
| On-prem verifier | DONE | | `deploy/onprem` — self-contained Helm values + `docker-compose.yml` + air-gap image mirror (`mirror-images.sh`, `images.txt`) for a customer-hosted attestation verifier; `docs/deployment-onprem.md` |
| Raw event retention controls | DONE | | Per-tenant `raw_retention_days` + platform default `KSEAL_RAW_RETENTION_DAYS`; interface-driven purge routine (fake-clock testable) deletes raw events past the window, retains aggregates, tenant-isolated; also purges orphaned deleted-tenant raw events |
| Policy packs | DONE | | `kseal policy pack {list,show,diff,apply,bulk-apply}` over 4 embedded vertical packs (fintech/gaming/health/media), idempotent + fault-isolated bulk-apply with `--dry-run`, composed over existing policy RPCs (no server change); `docs/policy-packs.md` |
| Compliance dashboards | DONE | | `web/console` ships five tenant-scoped views (audit trail + `VerifyAuditChain`, data-processing registry, MASVS evidence, kill-switch control, canary monitor) reading the canonical `kseal.v1.ComplianceService` client directly (the `kseal-cli` compliance commands likewise). GA-polished: a guided **"Secure your app" onboarding** stepper, an explicit **"chain verification unavailable"** indicator in the audit-trail view, WCAG AA accessibility, dark/light theming, full loading/empty/error states, and visual-regression tests. Graceful degradation is preserved (`UNIMPLEMENTED`/`UNAVAILABLE` → clean "not available yet"); kill-switch issuance stays request-only (server holds the Ed25519 signing authority). MASVS evidence also available via `tools/masvs-report` + `kseal build masvs`; `docs/compliance-console.md` |
| Partner / MSSP console | DONE | | `web/partner-console` — read-only React/Vite MSSP app, client-side fleet rollups over per-tenant `QueryService` reads (worst-first tenant health), reuses console request-proof/auth. GA depth + polish: fleet→tenant→signal drill-downs, saved views/filters, CSV/JSON export, client-side alert thresholds, WCAG AA + responsive + dark/light; `docs/mssp-console.md` |

---

## Phase 5: Desktop (6+ months after mobile maturity)

**Status: DONE | 100%**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| macOS SDK | DONE | | `sdk/desktop/macos` — SwiftPM `KsealDesktop`: SecCode/SecStaticCode signature validity, team id, notarization, hardened-runtime, dylib-injection probes → Rust core via FFI → `TrustService`; public APIs only (App Store / Gatekeeper safe) |
| Windows SDK | DONE | | `sdk/desktop/windows` — .NET 8 `Kseal.Desktop`: WinVerifyTrust Authenticode (incl. real PKCS#7 timestamp extraction), publisher/thumbprint, pure-managed PE header/section integrity, DLL-injection probes; binds the same C ABI via P/Invoke |
| Desktop API attestation | DONE | | Both desktop SDKs establish a trust session over the existing `TrustService` RPCs, fusing local integrity signals through the Rust core (same path as mobile) |
| Code integrity | DONE | | macOS bundle signature/notarization + Windows Authenticode/PE section integrity verification (see macOS/Windows SDK rows) |
| Secure updater integration | DONE | | `sdk/desktop` secure updater: Ed25519 verify-before-apply over a signed update channel (macOS + Windows), fail-closed on signature/rollback failure; `docs/desktop-secure-update.md` |
| Enterprise compatibility controls | DONE | | MDM-friendly `EnterprisePolicy` providers (macOS + Windows) that fail-closed to strict policy on read errors and reject allowlist prefix-escape; defers aggressive anti-debug per the desktop caution; `docs/desktop-sdk.md` |
| Hardware-bound proofs | DONE | | TPM (Windows) / Keychain (macOS) hardware-bound attestation keys backing desktop request proofs |

---

## Change Log

| Date | Change |
|---|---|
| 2026-06-12 | Initial documentation set created: README, PROPOSAL, ARCHITECTURE, PROGRESS, and project scaffold. Phase 0 marked IN PROGRESS. |
| 2026-06-13 | Full platform delivery merged to `main` and verified end-to-end. **Phase 0 → DONE** (threat model, MASVS mapping, iOS/Android policy reviews, parity matrix, cost model, Rust startup benches, attestation prototype). **Phase 1 → DONE** (all 11 server + SDK modules: registry, trust sessions, Play Integrity + App Attest verifiers, signed request proof, signed config, ingest, query, webhooks, Android/iOS SDKs, Rust trust core, React console). **Phase 2 → IN PROGRESS ~88%** (7 runtime-protection modules done across the Rust core + mobile probes + policy simulator + false-positive guardrails; SIEM integration not started). Added the real end-to-end integration suite under `tests/` (trust flow + anti-replay, telemetry ingest/query with quota, signed config, webhook delivery + retry, query overview + cross-tenant isolation, privacy contract) running against Postgres 16 + Redis 7 via testcontainers. |
| 2026-06-13 | Second delivery wave (5 parallel workstreams) merged to `main`. **Phase 2 → DONE** — SIEM integration (`server/data-plane/siem`): per-tenant export to Splunk HEC / Microsoft Sentinel / Elastic, backpressured + batched + at-least-once with per-tenant circuit breaker, privacy allow-list (no PII), connector templates. **Phase 3 → IN PROGRESS ~78%** — Gradle (`plugins/gradle`) + Xcode (`plugins/xcode`) build-time hardening plugins (R8-aware obfuscation, AES-GCM string/resource sealing, symbol/metadata stripping, per-build HKDF polymorphism seed), shared `kseal.build-proof/v1` manifest registered via `RegistryService.CreateBuild`, and the CI release gate (`.github/workflows/release-gate.yml`); native CFI/MTE hardening + MASVS evidence report still pending. Added the **`cmd/kseal-cli`** operator CLI (tenant/app/build/policy/simulate/webhook/events) and the **`deploy/`** foundation (Helm chart with HPA/PDB/NetworkPolicy, Terraform modules, Prometheus/Grafana observability) as enabling infrastructure. Fixed a server bug surfaced by the CLI: the observability interceptor dereferenced a typed-nil `*connect.Response` on the error path, masking every errored RPC as `Internal`. |
| 2026-06-13 | Third delivery wave (5 disjoint workstreams) merged to `main`. **Phase 3 → DONE** (native `.so` CFI/MTE/BTI/PAC posture + Mach-O section-hash integrity; `tools/masvs-report` per-release MASVS evidence generator). **Phase 4 → IN PROGRESS ~78%** (CMK/BYOK with per-tenant KMS-wrapped DEK + fail-closed; multi-region Terraform + global routing; private-link; on-prem/air-gapped verifier bundle + DR runbooks; per-tenant raw-event retention; vertical policy packs; read-only partner/MSSP console). **Phase 5 → IN PROGRESS ~67%** (macOS + Windows desktop SDKs with code-signature/notarization/Authenticode/PE integrity, desktop trust-session attestation over the existing RPCs). Server hardening also added behind default-off env vars: Redis TLS/AUTH, OTLP trace exporter; wired additively into Helm/compose by the deploy stream. Remaining: dedicated tenant tiers, compliance dashboards, secure-updater integration, enterprise compatibility controls. |
| 2026-06-13 | Fourth delivery wave (6 disjoint workstreams) merged to `main`, explicitly graded against the competitor parity matrix. **Phase 5 → DONE (100%)** — desktop secure-updater (Ed25519 verify-before-apply, fail-closed), MDM enterprise compatibility controls, and TPM/Keychain hardware-bound proofs complete the desktop SDKs. **Phase 4 → IN PROGRESS ~95%** — new `ComplianceService` backend (hash-chained tamper-evident audit trail + data-processing registry with `VerifyAuditChain`, Ed25519 anti-rollback signed kill switch, deterministic canary rollout + guardrail-driven auto-rollback, HKDF per-tenant dedicated/regulated tier; additive proto, flag-gated/fail-safe, all RPCs API-key-authed + tenant-scoped); compliance NoOps tooling (iOS privacy-manifest, Google Data-Safety, MASTG runner + CLI); five compliance/ops console views + UX polish; build-hardening depth (per-build bytecode obfuscation, broader native posture verification, build-proof v2); and product polish (runnable sample apps, docs site, refreshed parity matrix). Remaining for Phase 4: re-point the console/CLI compliance surfaces from their stream-local proto onto the canonical `kseal.v1.ComplianceService` client. |
| 2026-06-13 | Compliance canonical re-point merged (#41), completing the Wave 4 follow-up. The `web/console` views and `kseal-cli` compliance commands now read the canonical `kseal.v1.ComplianceService` directly (reconciled field/RPC/pagination shapes: keyset audit list + dedicated `VerifyAuditChain`, unpaginated data-processing registry, `KillSwitchCommand`/`CanaryState` enums, single `GetCanaryStatus`); dead stream-local proto/gen artifacts removed from both surfaces. Graceful degradation preserved (`UNIMPLEMENTED`/`UNAVAILABLE` → "not available yet"); kill-switch issuance stays request-only (server holds Ed25519 signing authority). **Phase 4 → DONE (100%)** — `Compliance dashboards` now reads the live backend, closing the last open Phase 4 module. |
| 2026-06-15 | **Fleet Anomaly Guard + risk-bit contract** — population-level abuse detection added to close the one capability top-tier abuse-defense players (Approov/Castle/Arkose) have and the per-instance trust path lacked. `server/data-plane/fleet` learns per-`(tenant, app, build, region)` cohort baselines and trips on either a per-signal surge (EWMA baseline) or a volume-velocity spike (coordinated flood of individually-clean clients); a server-derived `FLEET_ANOMALY` bit is fused into newly joining clients (graduated step-up). O(1)/event, sharded LRU-bounded memory, in-process/per-replica; `kseal_fleet_anomaly_active{tenant,app,build,region}` gauge + OTel span attrs + console Overview *Fleet anomalies* panel; flag-gated (`fleet_anomaly`), default off. Also fixes the latent dual risk-bit-namespace foot-gun: a single source-of-truth `risk.FromWire` now translates the device/wire `RiskBitset` layout (Rust core, bits 0..15) into the server layout (bits 0..10) at every device→server boundary (trust + ingest) before fusion/scoring, pinned by Go + Rust contract tests. `docs/fleet-anomaly.md`, `docs/risk-bit-contract.md`. |
| 2026-06-13 | Fifth delivery wave (6 disjoint workstreams, #43–#48) merged to `main` — "Top-Tier Polish & Parity": raising every surface to public, GA-grade, equal-or-better than top-tier incumbents. All six phases remain **DONE**; this wave is polish + production-grade scale on top. **Production data plane** (#48): real Kafka/Redpanda broker (at-least-once, tenant-partitioned, idempotent + load-shedding) + ClickHouse analytics/raw-event store (`ReplacingMergeTree` → effectively-once, `tenant_id`-leading isolation, monthly partitions + TTL/retention) + real OTLP spans/metrics — all behind the existing `Broker`/`AnalyticsStore`/`EventSink` interfaces, selected via `KSEAL_BROKER`/`KSEAL_ANALYTICS` (default off, fail-closed), zero proto change; compose `dataplane` profile + additive Helm/Terraform (MSK Serverless, ClickHouse PrivateLink) + testcontainers suite; `docs/data-plane-scale.md`. **Operator console GA** (#45): guided "Secure your app" onboarding stepper, explicit "chain verification unavailable" indicator, WCAG AA, dark/light, full loading/empty/error states, visual-regression tests. **MSSP console depth** (#44): fleet→tenant→signal drill-downs, saved views, CSV/JSON export, alert thresholds + polish. **CLI/NoOps DX to GA** (#47): `kseal init`/`doctor` guided flow, `--output table/json/yaml`, config profiles, shell completions, actionable errors. **SDK ergonomics** (#43): runnable sample apps + "secure in ~5 min" quickstarts (Android/iOS/macOS/backend under `examples/`), typed error taxonomy, semver/changelog, stable FFI ABI. **Build-hardening GA + docs site** (#46): plugin DX + reproducible builds + broader native verification, a polished public docs site with a guided "secure your app" walkthrough (`site/`), and an honest refreshed `docs/feature-parity-matrix.md`. Follow-up #49: console same-origin API default + Vite dev proxy to remove a CORS "Failed to fetch" in local dev. |
