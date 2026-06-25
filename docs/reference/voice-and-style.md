# Documentation voice & style

This is the contract for how kseal's external-facing documentation is written.
It exists so the whole corpus reads as one voice and every claim is anchored to
something real. Anyone editing the docs should follow it.

## 1. Present tense, no phase or version narrative

Describe the product **as it is today**. The reader does not care how it was
built, in what order, or across which milestones.

- Write: *"kseal scores risk on the server and returns a trust decision."*
- Not: *"Phase 5 added server-side scoring."* / *"In v2 we introduced…"* /
  *"This was previously deferred but is now delivered."*

There are no "Delivered state" callouts, no "Phase N", no roadmap framing in the
external docs. If a capability exists, state it plainly. If it does not exist
yet, simply don't describe it — never document a future or a history.

## 2. Every number is grounded

No invented figures. Each performance number, weight, threshold, or footprint
either:

- traces to [`reference/benchmarks.md`](benchmarks.md) (measured, with the
  command to reproduce it) or [`reference/risk-signals.md`](risk-signals.md)
  (taken from `risk.go`), or
- is clearly labelled a **budget** (a target the design holds itself to), never
  presented as a measurement.

When in doubt, cite the fixture or the source file. Prefer "tens of nanoseconds
(`policy_evaluate`, ~48 ns)" over a vague "extremely fast".

## 3. One canonical customer: Meridian Pay

All examples use a single fictional deployment so the reader builds one mental
model instead of meeting a new company per page.

**Meridian Pay** — a consumer payments app.

- `tenant_id`: `meridian`
- apps: `pay-android`, `merchant`
- regions: US, DE, BR, IN, SG
- SOC stack: Splunk (HEC)
- enforcement mode: `STEP_UP`

The reproducible identifiers (`build_hash`, `policy_hash`, `install_key_hash`,
`coarse_time_bucket`) and the five canonical device scenarios D1–D5 live in
[`reference/fixtures/`](fixtures/README.md). Use those exact values — don't make
up new hashes or new customers.

## 4. Examples come from the committed fixtures

When a doc shows a payload, an event, a webhook body, or a decision, it should
be the committed fixture (or a faithful excerpt of it), and it should link to
the fixture file. The fixtures are byte-exact and independently verifiable, so
the prose stays trustworthy:

- trust handshake → [`reference/fixtures/trust/`](fixtures/trust/)
- risk events & telemetry → [`reference/fixtures/events/`](fixtures/events/)
- webhook & SIEM egress → [`reference/fixtures/egress/`](fixtures/egress/)
- policy & signed config & kill switch → [`reference/fixtures/control/`](fixtures/control/)

## 5. Audience and tone

The reader is a developer or security engineer **integrating kseal**, not an
internal stakeholder.

- Confident and concrete; explain a term the first time it appears, then use it.
- Lead with what the reader can do and why it matters, then how it works.
- No marketing superlatives without a number behind them.
- Short sentences. Tables for contracts. Code blocks for payloads and commands.

## 6. Vocabulary (use these consistently)

- **Four planes**: Build, Device, Data, Control.
- **Trust decision**: `ALLOW` / `STEP_UP` / `DENY` (not "block"/"pass").
- **Trust levels**: `TRUSTED`, `LOW_RISK`, `MEDIUM_RISK`, `HIGH_RISK`,
  `CRITICAL`.
- **Enforcement modes**: `OBSERVE`, `STEP_UP`, `BLOCK`.
- **Risk bits**: device/wire layout (0–20) vs. server layout — always note that
  the device layout is translated via `FromWire` before scoring.
- **RASP probes**: the on-device modules; name them as they appear in code.
- Product name is lowercase **kseal** everywhere, including sentence starts.
