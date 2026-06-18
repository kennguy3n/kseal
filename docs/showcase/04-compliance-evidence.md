# Compliance evidence — turning a build into MASVS proof

**Meridian Pay team:** Compliance / AppSec. Faces auditors, payment-network reviews, and
security questionnaires from enterprise partners, against OWASP-MASVS expectations.
**Job to be done:** *"For every release I ship, prove our OWASP-MASVS coverage and document
exactly what data we process and how long we keep it — without a manual evidence-gathering
fire drill every audit."*

The deployment is the canonical [Meridian Pay reference](../reference/fixtures/README.md):
tenant `meridian`, apps `pay-android` and `merchant`, regions US/DE/BR/IN/SG.

---

## The problem

A regulated payments app lives and dies by evidence. When an auditor or an enterprise partner
asks *"do you meet MASVS-STORAGE? MASVS-RESILIENCE? what personal data do you process?"*, the
answer can't be a slide deck written from memory. It has to be **derived from what actually
shipped** and tied to a specific, identifiable build. Hand-maintained compliance spreadsheets
are both a time sink and a liability — they drift from reality the moment a build changes.

---

## What the compliance team does in kseal

### MASVS coverage, derived from the build itself

When Meridian registers a release build, the build carries a **build-proof manifest** — the
hardening module set compiled into the release plus the applied code transforms — anchored to
the same `build_hash` every trust decision references
(`e3bb7952…a70d73`, the `pay-android` build used throughout these chapters). kseal maps that
manifest onto OWASP-MASVS categories — *the same evidence the report generator under
`tools/masvs-report/` emits* — and surfaces it in the console:

- **Coverage: 8/8** MASVS categories with build evidence.
- Each category — **STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY** — is
  marked **Evidenced**, with the **specific modules** that evidence it (e.g. `MASVS-RESILIENCE`
  ← `anti-hooking, integrity, jailbreak, rasp`).
- **Applied transforms** are listed explicitly: `control-flow-flattening`,
  `string-obfuscation`, `symbol-strip` — the same hardening passes the
  [build guide](../build-guide/00-index.md) documents.
- A **Gaps & notes** panel is honest about provenance: the evidence is derived from the
  registered build-manifest module set and the `build_hash` proof — it does not over-claim
  per-control signed attestation artifacts it doesn't have.

That last point matters for a compliance tool: it states exactly what the evidence *is* and
*isn't*, which is what keeps an auditor's trust. (The coverage starts at 0/8 if a build is
registered with an empty manifest — a real defect that was found and fixed via this very drive;
see [defects found](defects-found.md).)

### A data-processing registry that documents itself

The data-processing registry records each processing activity — a tenant-default
`app_abuse_prevention` record and an app-scoped record for `pay-android` — both declaring
**"Aggregates only"** retention, consistent with the minimized telemetry contract in
[`events/risk-event.json`](../reference/fixtures/events/risk-event.json) (no device ID, IP,
advertising ID, or raw PII). This is the artifact that answers the privacy/DPIA questions in a
security questionnaire, kept *in the platform* next to the controls it describes.

### Every change is evidence, too

Registering those data-processing records produces **hash-chained audit entries**, and the
console re-verifies the chain on load (entries are cryptographically linked with no gaps or
edits — the same mechanism the [incident-response
chapter](03-incident-response-and-kill-switch.md) relies on). So the *act of documenting* is
itself tamper-evident.

---

## How the incumbents handle this

| Capability | kseal | Guardsquare/Appdome | Approov | Castle/Arkose |
|---|---|---|---|---|
| OWASP-MASVS coverage **derived from the actual build** | **Built-in** | Hardening reports, partial mapping | Not the focus | N/A |
| Coverage tied to an identifiable signed build-hash proof | **Yes** | Varies | N/A | N/A |
| In-product data-processing / retention registry | **Built-in** | No | No | No |
| Tamper-evident audit of compliance changes | **Built-in** | DIY | DIY | Partial |
| Honest provenance (states what evidence is/isn't) | **Yes** | Varies | N/A | N/A |

App-hardening vendors can produce hardening reports, but a self-documenting **MASVS-from-
build-proof view plus a data-processing registry plus a tamper-evident change log**, in one
place, aimed at the compliance owner, is not something a lean team would otherwise get without
assembling tools and maintaining spreadsheets.

---

## Back-tested evidence

Compliance evidence that can't be reproduced isn't evidence — so the view is derived from
tested code and is honest about its own provenance (full numbers in
[Evidence & back-testing](evidence-and-backtesting.md)):

- **The minimization claim is a test, not a promise.** `privacy_contract_test.go` asserts the
  telemetry schema carries **only minimized, non-PII fields** — the machine-checked backing for
  the registry's "Aggregates only" retention records.
- **The change log is tamper-evident by construction.** Registering each data-processing record
  writes a hash-chained audit entry (`server/control-plane/compliance/`) that the console
  re-verifies on load — so the *act of documenting* is itself evidence.
- **The view states what it isn't.** Coverage (8/8) is derived from the registered
  build-manifest module set and the `build_hash` proof; the *Gaps & notes* panel explicitly
  declines to claim per-control signed attestation artifacts it doesn't have — the same
  evidence the report generator under `tools/masvs-report/` emits.

---

## Why it wins for the compliance team

- **Evidence, not memory.** MASVS coverage is derived from what actually shipped and tied to a
  signed `build_hash`.
- **Audit-ready honesty.** The view states its own provenance and gaps — exactly what keeps
  auditors comfortable.
- **No evidence fire drill.** Data-processing records and a verifiable change log live in the
  platform, ready when the questionnaire arrives.

> JTBD met: *every release proves its MASVS coverage and documents its data processing,
> derived from the build itself — no manual evidence gathering.*
