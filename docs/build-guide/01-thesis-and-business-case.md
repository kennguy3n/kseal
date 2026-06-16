# Chapter 1 — The thesis & the business case

> **The decision:** Should app protection live on the device, on the server, or both — and
> is there a business big enough to justify building a platform around the answer?

---

## Start from the uncomfortable truth

Any check that runs **only** on a device the attacker controls can eventually be defeated.
Root/jailbreak detection, debugger detection, integrity checks, "is this a real app?" logic
— given a rooted device, a hooking framework (Frida, Xposed, objection) and a disassembler,
a motivated attacker patches it out, hooks around it, or emulates it. This isn't pessimism;
it's the premise the entire mobile-shielding industry quietly operates on.

So the design question isn't *"how do we make the client unbreakable?"* (you can't). It's:

> **How do we make breaking the client *necessary but not sufficient* to abuse the backend?**

That reframing is the whole product. The winning design:

1. **Combines local checks with backend verification.** The device gathers signals; the
   *server* makes the trust decision. You can't patch the server from a phone.
2. **Uses per-build polymorphism.** Every protected build is structurally different, so a
   bypass crafted against one build doesn't transfer to the next — turning a "one-time crack"
   into "recurring effort."
3. **Binds API access to a server-side trust decision.** Access to protected APIs is gated by
   a short-lived, server-issued trust token encoding *app instance identity + build hash +
   risk state + a server nonce + the active policy*. A cracked client can't mint its own
   trust.
4. **Anchors to an open standard.** Build against the
   [OWASP MASVS](https://mas.owasp.org/MASVS/) — testable and vendor-neutral — not a
   proprietary checklist. MASVS-RESILIENCE explicitly frames obfuscation and anti-tamper as
   *defense-in-depth that raises attacker cost*, not as a primary control.

If you internalize only one thing before writing code: **the client's job is to gather
evidence honestly and cheaply; the server's job is to decide.**

---

## The options on the table

| Approach | What it is | Why it's not enough on its own |
|---|---|---|
| **Client-only shielding** (obfuscation + RASP) | Make the binary hard to analyze and tamper with | Bypassable given time; the *decision* still lives on the attacker's device |
| **Platform attestation only** (Play Integrity / App Attest) | Trust the OS vendor's verdict | A raw signal, not a decision; no fleet view, no policy, no response, no evidence |
| **Account-abuse platforms** (behavioral/population) | Detect bad *accounts* by behavior | Not app-integrity or attestation; expects analysts to tune |
| **Server-authoritative trust** (this platform) | Fuse all of the above into a server-side decision bound to each request | Requires building the decision plane — but it's the only one that's *not* bypassable by owning the client |

The incumbents each own one of the first three columns. None of them, alone, is the whole
job — which is exactly the opening.

---

## Who pays for this, and why

The technical thesis only matters if a buyer exists. The wedge is the **SME-at-scale, NoOps**
segment: teams with **millions of installs but no security analysts and no ops budget**.

- A fintech wallet, a fast-growing fitness app, a mobile game, a regulated health app, a
  high-traffic store — all are high-value targets, and all face the *same* attacks the
  enterprise faces.
- But they **can't** do what the enterprise does: buy an obfuscator, a separate attestation
  product, an abuse-detection platform, stand up a data lake, and hire analysts to wire them
  together.
- The incumbents are priced and staffed for the org that *already has* a security team. For
  the SME, "buy four products and hire an analyst" is a non-answer.

So the business thesis mirrors the technical one:

> **Deliver the whole job — attestation → fleet analytics → response → compliance — in one
> product, zero-config, operable by one engineer, at SME economics.**

That's a different *shape* of product than any single incumbent, which is what makes it
defensible rather than a feature race.

---

## What "good" has to mean (the constraints that follow)

Committing to that buyer forces hard constraints that the rest of this series has to honor:

- **Zero-config or it doesn't count.** A NoOps founder will never tune baselines, write
  correlation rules, or stand up a pipeline. Defaults must be safe and useful on day one
  (see [Chapter 5](05-data-plane-ingest-fleet-and-risk.md) on learned baselines).
- **Invisible on the device.** No launch-time network call, single-digit-MB memory,
  sub-40 ms p95 startup overhead — protection that hurts UX gets ripped out
  (see [Chapter 3](03-device-plane-rasp-and-rust-core.md)).
- **Cents per thousand MAU.** The data-plane bill has to stay near-flat as MAU grows, or the
  SME economics collapse (see [Chapter 8](08-cost-scale-and-noops-economics.md)).
- **Privacy as a feature, not a liability.** Fingerprint-heavy SDKs create regulatory risk;
  minimization is a selling point to exactly this buyer
  (see [Chapter 7](07-privacy-and-compliance.md)).

---

## The business read

- **The market gap is real and structural**, not a feature gap. Each incumbent is *correctly*
  optimized for a buyer with a security team; the un-served buyer is the one who can't staff
  the integration.
- **The moat is "the whole row, cheap, NoOps,"** not "best obfuscator." You will not win a
  head-to-head obfuscation bake-off with Guardsquare, and you shouldn't try. You win by being
  the only credible *one-product* answer for the SME.
- **The constraints are the product.** Zero-config, invisible, cheap, private — these aren't
  nice-to-haves bolted on later; they're the spec, and every subsequent chapter is a
  consequence of taking them seriously.

Next: [Chapter 2 — Architecture: the four planes](02-architecture-four-planes.md), where the
thesis becomes a system you can draw on a whiteboard.
