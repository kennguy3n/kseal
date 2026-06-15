# Changelog — kseal platform (server / data-plane)

All notable operator-facing changes to the kseal server and data plane are
documented here. This file complements the per-SDK changelogs
(`sdk/*/CHANGELOG.md`) and follows
[Semantic Versioning](https://semver.org) and the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

Entries here focus on changes that affect how operators deploy, upgrade, or
integrate with the platform (wire/egress contracts, storage schema, broker
codecs, rollout ordering). Pure internal refactors are out of scope.

## [Unreleased]

### Changed

- **Egress `risk_bits` is now the server scoring layout (not the device/wire
  layout).** Webhook and SIEM payloads previously leaked the raw device-reported
  bitset; both paths now normalize to the server layout before emitting, so
  `risk_bits` carries server semantics going forward. The bit positions differ
  between layouts — most notably **bit 4 is `app_tamper` in the server layout,
  where the old wire layout meant `debugger`**. Any downstream rule that parses
  numeric `risk_bits` positions must move to the server layout, or — preferably
  — switch to the new name-based `risk_signals` field and stop depending on bit
  positions entirely. See `docs/risk-bit-contract.md`.

### Added

- **Name-based egress signals (`risk_signals`).** Webhook and SIEM payloads now
  emit a stable, name-based view of the risk bits (e.g.
  `["debugger","app_tamper"]`) alongside the raw integer. Names are the external
  contract; bits can be renumbered safely. Splunk / Sentinel / Elastic
  onboarding templates map the field (multivalue / `dynamic` / `keyword`).
  - *SIEM connectors with an explicit `field_allow_list` are opt-in:* the
    allow-list only ever narrows, so an existing connector keeps emitting its
    stored fields until it is re-registered (or has `risk_signals` added to its
    list). Connectors with an empty allow-list pick the field up automatically.
    See `docs/siem-integration.md`.
- **Webhook `risk_level`.** Webhook payloads gained the fused trust level for
  parity with the SIEM export, so consumers can correlate on the level without
  re-deriving it from `risk_bits`.
- **Self-describing stored risk bits (`risk_bits_layout`).** Stored telemetry
  rows now carry a layout marker (`risk_bits_layout`, ClickHouse
  `UInt8 DEFAULT 0`) so a row is unambiguous about whether its bits are wire- or
  server-layout, and readers normalize on read. Pre-existing rows materialize
  `LayoutUnknown` (read as server layout), matching prior behavior, so the
  migration is additive. The column is added idempotently and gated behind a
  node-local `system.columns` probe, so steady-state server boots issue no DDL.

### Upgrade notes

- **Strict webhook deserializers** (those that reject unknown JSON fields) must
  be updated to tolerate the additive `risk_level` and `risk_signals` fields.
  Lenient consumers are unaffected.
- **Broker codec is now v2 (rolling-upgrade ordering matters).** The v2 decoder
  reads v1 records, but a still-running **v1 decoder cannot read a v2 record** —
  it drops it as a poison record. Upgrade the broker tier
  **consumers-before-producers**, or roll the consumer group atomically (old pod
  stops, new pod resumes from the committed offset). Running old + new consumers
  concurrently on the same group can lose v2 records the old pods fetch. This
  only affects the broker hop; the ingest fleet produces and consumes the same
  internal format, so a standard rolling deploy of ingest is safe. See
  `docs/risk-bit-contract.md`.
