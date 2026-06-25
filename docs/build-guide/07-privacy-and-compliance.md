# Chapter 7 — Privacy & compliance as features

> **The decision:** Security SDKs are notorious for hoovering up data and creating regulatory
> liability. How do you make data-minimization and compliance *selling points* — for exactly
> the regulated SME buyer — instead of a checkbox you bolt on before an audit?

---

## Privacy is a design constraint, enforced on the device

The temptation in this category is to fingerprint aggressively: more identifiers, more
cross-tenant linkage, more raw events "in case we need them." That's a liability magnet, and
for a health or fintech buyer it's disqualifying. So minimization is a constraint from the
start, and — critically — it's enforced **at the source**, not hoped for downstream.

- **PrivacyGuard on device** (`sdk/rust-core/kseal-core/src/events.rs`) drops disallowed fields
  *before* anything is serialized or transmitted. The minimized contract is what leaves the
  phone — there's no "we'll filter it server-side" gap to leak through.
- **No cross-tenant fingerprinting; tenant-scoped rotating identifiers.** Identity is scoped to
  a tenant and rotates; the platform deliberately can't build a global cross-app profile.
- **Aggregates, not per-user records, for population work.** Fleet anomaly detection
  ([Chapter 5](05-data-plane-ingest-fleet-and-risk.md)) introduces *no* new per-user identifier
  — it works on cohort aggregates, so the headline capability creates no privacy debt.

The minimization claim is machine-checked: `tests/privacy_contract_test.go` asserts the
telemetry schema carries **only** minimized, non-PII fields. If someone adds a sensitive field
to the wire contract, the test fails. Privacy is a *test*, not a promise.

---

## Compliance derived from what actually shipped

Hand-maintained compliance spreadsheets drift from reality the moment a build changes. The
better design derives evidence from the artifact itself.

- **MASVS coverage from the build proof.** When a build registers, its build-manifest module
  set + applied transforms map onto OWASP-MASVS categories (STORAGE, CRYPTO, AUTH, NETWORK,
  PLATFORM, CODE, RESILIENCE, PRIVACY). The console surfaces the coverage, tied to the signed
  `build_hash` — *the same evidence the report generator under `tools/masvs-report/` emits.*
- **A data-processing registry that lives in the platform.** Each processing activity (e.g.
  `app_abuse_prevention`, `clinical_access_integrity`) is recorded with its retention posture
  ("Aggregates only") next to the controls it describes — the artifact that answers the DPIA
  questions in a security questionnaire.
- **Store-disclosure artifacts, automated.** `tools/privacy-manifest/` generates the iOS
  `PrivacyInfo.xcprivacy`; `tools/datasafety/` helps with the Play Data Safety disclosure.
  These are derived, not authored by hand.

### The honesty that keeps an auditor's trust

The MASVS view's *Gaps & notes* panel explicitly states that coverage is derived from the
registered build-manifest module set and the build-hash proof, and that it does **not** ship
per-control signed attestation artifacts it doesn't have. A compliance tool that over-claims is
worse than useless — stating exactly what the evidence *is and isn't* is what keeps an auditor
comfortable. (See [Compliance evidence](../showcase/04-compliance-evidence.md).)

And because every compliance mutation is a hash-chained audit entry
([Chapter 6](06-control-plane-registry-policy-audit.md)), *the act of documenting is itself
tamper-evident.*

---

## Anchoring to an open standard, on purpose

kseal maps to **[OWASP MASVS](https://mas.owasp.org/MASVS/)** — open, testable, vendor-neutral
— rather than a proprietary vendor checklist (`docs/masvs-mapping.md`, `docs/masvs-evidence.md`,
plus the MASTG procedure runner `tools/mastg/`). MASVS-RESILIENCE explicitly frames obfuscation
and anti-tamper as *defense-in-depth that raises attacker cost*, not as a primary control —
which keeps the platform honest about what hardening does and doesn't buy.

---

## The business read

- **Minimization is a sales asset to the regulated buyer**, not a constraint. "We can't build a
  cross-app profile even if subpoenaed, and here's the test that enforces it" is a stronger
  pitch to a health/fintech CISO than any feature.
- **Compliance-from-build-proof removes an entire recurring cost** — the per-audit evidence
  fire drill. You're selling back the buyer's time, which is the scarcest thing an SME has.
- **Honest provenance is the differentiator vs marketing-grade "compliance" features.** Stating
  the gaps is counter-intuitively what wins the deal with a sophisticated buyer, because it's
  what survives an auditor's scrutiny.

Next: [Chapter 8 — Cost, scale & NoOps economics](08-cost-scale-and-noops-economics.md), where
all these choices have to add up to a bill an SME can pay.
