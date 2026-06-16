# Chapter 9 — Business scenarios: making the call vs the incumbents

> **The decision:** Architecture decisions are really *business* decisions in disguise. This
> chapter puts five of them in concrete rooms — a buyer, a budget, a competitor on the table —
> and shows the trade-off we took and why. It's the chapter to read if you're deciding whether
> to **build, buy, or position** a platform like this.

For each scenario: the room, the options, the call, and the honest cost of the call.

---

## Scenario 1 — "Just buy Guardsquare and ship"

**The room.** A founder asks: the market leaders (Guardsquare DexGuard/iXGuard, Promon,
Appdome, AppSealing) are excellent at obfuscation and RASP. Why build anything?

**The options.**
- *Buy a hardener.* Best-in-class binary protection, fast to adopt.
- *Build server-authoritative trust.* Slower, but moves the decision off the device.

**The call.** Build the trust decision; don't try to out-obfuscate the leaders. A hardener
makes the client *harder to break* — but the trust *decision* still lives on the attacker's
device, so it's bypassable given time ([Chapter 1](01-thesis-and-business-case.md)). We use
hardening as *defense-in-depth* (per-build polymorphism raises attacker cost) and put the
un-bypassable part — the server-side decision bound to each request
([Chapter 4](04-trust-protocol-attestation-and-proofs.md)) — at the center.

**Honest cost of the call.** We will *not* win a head-to-head obfuscation bake-off, and we
shouldn't claim to. The [feature-parity matrix](../feature-parity-matrix.md) marks secret
protection (white-box vaults) as only *partial* for kseal versus Guardsquare/Promon. We accept
that, because the buyer we're after needs the *whole job*, not the deepest single pillar.

---

## Scenario 2 — "We have no analysts. Who tunes the abuse rules?"

**The room.** A solo-founder fitness app with millions of installs. The abuse-detection
incumbents (Castle, Arkose) are strong — but every demo assumes an analyst tuning thresholds.

**The options.**
- *Sell knobs.* Expose thresholds, cohorts, rules — maximum flexibility.
- *Learn the baseline.* Zero knobs; the engine learns normal and flags the break.

**The call.** Learn the baseline. The buyer will *never* tune knobs, so a knob is a feature
that doesn't exist for them. Fleet Anomaly Guard learns per-cohort baselines and auto-steps-up
on a break, O(1)/event ([Chapter 5](05-data-plane-ingest-fleet-and-risk.md)). "Zero-config or
it doesn't count" is a product law here, not a preference.

**Honest cost of the call.** A sophisticated security team that *wants* to hand-tune has less
surface to do it. We're explicitly not optimizing for them — they're the incumbents' buyer, not
ours. Defaults that are safe and useful beat knobs that go untouched.

---

## Scenario 3 — "Sign every token with the KMS — it's the secure default"

**The room.** A security review insists every trust token be signed by the cloud KMS/HSM on
every issuance. It *sounds* like the conservative choice.

**The options.**
- *KMS sign per token.* Maximum key custody, audited per call.
- *In-process signing with rotated, HSM-released keys.* Keys never leave the boundary; signing
  is local.

**The call.** In-process signing. At 100M MAU, "KMS per token" costs **thousands of
dollars/month** and adds latency to the hot path — it would quietly kill the SME unit economics
([Chapter 8](08-cost-scale-and-noops-economics.md)). Keys are still HSM-released and rotated;
custody is preserved; KMS op volume scales with the **tenant** count (~5k), not MAU. Proofs
verify against cached public keys, so verification is ~444 ns and free of network round-trips.

**Honest cost of the call.** Slightly more key-management machinery (rotation, caching,
revocation) to build and reason about. We take that one-time complexity to avoid a recurring
per-request cost that would make the product unaffordable.

---

## Scenario 4 — "Ship the stricter policy to everyone Monday"

**The room.** A release engineer at a high-traffic store needs a stricter trust policy live,
but a too-strict policy blocks real customers at checkout. The incumbent answer is "bolt on a
feature-flag/experimentation tool."

**The options.**
- *Flip globally.* Simple, but you find out at full blast.
- *Build progressive delivery into the trust layer.* Stage %, watch a guardrail, auto-revert.

**The call.** Build canary + auto-rollback *into* the trust layer
([Chapter 6](06-control-plane-registry-policy-audit.md)): deterministic per-instance bucketing,
a block-rate guardrail, and an auto-revert to last-known-good that writes a tamper-evident audit
entry. The SME shouldn't have to stand up a separate experimentation platform to change a
security policy safely.

**Honest cost of the call.** More control-plane surface (cohorting, a controller, guardrail
math) than "just flip a flag." But the alternative — a security change with no seatbelt — is
exactly the 2 a.m. incident the buyer can't staff for.

---

## Scenario 5 — "Collect everything; we might need it"

**The room.** Product wants richer telemetry "for analytics." A regulated-health buyer's CISO
is in the *next* room asking what personal data the SDK collects.

**The options.**
- *Collect broadly.* More data, more future optionality.
- *Minimize at the source, enforce by test.* Only non-PII, dropped on-device before send.

**The call.** Minimize, and make it a *test* (`privacy_contract_test.go`), with on-device
PrivacyGuard dropping disallowed fields before serialization
([Chapter 7](07-privacy-and-compliance.md)). For the regulated SME, a fingerprint-heavy SDK is
a *liability*, not an asset; "we can't build a cross-app profile, and here's the test that
enforces it" wins the deal.

**Honest cost of the call.** Some analytics you could have built, you can't — by design. We
trade speculative data optionality for a clean privacy posture that's a selling point to the
exact buyer we want.

---

## The pattern across all five

Every call resolves the same way: **optimize for the SME-at-scale, NoOps buyer, even when that
means deliberately *not* matching an incumbent on their strongest single axis.**

| Tempting default | Our call | Because |
|---|---|---|
| Buy the best obfuscator | Build server-side trust; use hardening as defense-in-depth | The decision must not live on the attacker's device |
| Sell tuning knobs | Learn baselines, zero-config | The buyer will never tune them |
| KMS-sign every token | In-process signing, rotated keys | Per-request KMS breaks SME economics |
| Flip policy globally | Canary + auto-rollback in the trust layer | A security change needs a seatbelt the SME can't staff |
| Collect everything | Minimize at source, enforce by test | Privacy is an asset to the regulated buyer, not a constraint |

> The throughline: each incumbent owns one column. We deliver the **whole row** — attestation
> → fleet analytics → response → compliance — zero-config, one engineer, at SME economics. The
> trade-offs above are the price of that focus, taken on purpose.

---

That's the series. To see these decisions *running*, read the
[capability showcase](../showcase/00-showcase-index.md); to check the claims, see
[Evidence & back-testing](../showcase/evidence-and-backtesting.md). To go deeper on any single
mechanism, the chapters here name the exact files in this repo.
