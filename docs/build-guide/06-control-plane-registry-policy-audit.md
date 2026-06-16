# Chapter 6 — The control plane: registry, policy, audit & response

> **The decision:** Where does the truth live — tenants, apps, builds, policies, keys — and
> how do you make every change to that truth **provable** to an auditor without a separate
> logging product?

---

## The source of truth

The control plane (`server/control-plane/`) is low-volume, strongly consistent, and owns the
secrets and policy. It's where the data plane gets everything it executes. Three pillars:

- **The registry** (`registry/`) — tenants, apps, builds, policies, API keys, webhooks. This
  is the relational source of truth (Postgres/CockroachDB). Control-plane RPCs require an API
  key (`Authorization: Bearer ksk_…`); an unauthenticated call returns `401`. The device-plane
  RPCs need no API key — they're scoped by `tenant_id` and gated by signed proofs.
- **Compliance & audit** (`compliance/`) — the hash-chained audit log and the data-processing
  registry (more below).
- **Policy authoring + the simulator** — policies are authored here and *signed* before the
  data plane or device ever sees them. The policy simulator (`server/data-plane/simulator/`)
  lets you test a rule change against historical traffic before promoting it.

Everything the control plane hands downstream is **signed** (Ed25519 config envelopes,
[Chapter 4](04-trust-protocol-attestation-and-proofs.md)). That's the invariant that lets the
high-volume data plane trust a policy it didn't author, and lets a device trust a kill switch
it receives over the wire.

---

## The build is identity: `build_hash` anchors everything

When a tenant registers a release build, it carries a **build proof** — the hardening module
set compiled in plus the applied transforms, identified by a `build_hash`. That hash is not a
label; it's the anchor for:

- **Trust decisions** — the trust token encodes the `build_hash`, so a repackaged build (a
  different hash) can't pass as the genuine one.
- **Compliance evidence** — MASVS coverage is derived from the registered build manifest and
  tied to that signed hash ([Chapter 7](07-privacy-and-compliance.md)).
- **Fleet cohorts** — `(tenant, app, build, region)` is the cohort key in
  [Chapter 5](05-data-plane-ingest-fleet-and-risk.md).

One identity, used everywhere, is what lets the platform answer "is this a genuine
`meditoken-2.2.0-rasp`?" consistently across trust, compliance and analytics.

---

## Response: the signed kill switch and the canary

Response controls are control-plane mutations that take effect on devices via signed config:

- **Signed remote kill switch** — armed/disabled from the control plane, *cryptographically
  signed* so clients verify the signature before honoring it; takes effect on the next
  attestation, globally, in seconds. An attacker can't forge a "stand down" or replay an old
  state. (See [GameForge](../showcase/03-gameforge-incident-response.md).)
- **Canary rollout with a guardrail** (`server/data-plane/canary/`) — stage a candidate policy
  to a slice of traffic, attribute every live decision to its cohort, and let a controller
  auto-roll-back if the candidate's block rate crosses a threshold with enough samples to be
  meaningful. Bucketing (`canary/bucket.go`, `InCanary(tenant, app, instance, percent)`) is
  deterministic per instance, monotonic in the percentage, and independent across tenants
  (`bucket_test.go`); the controller is tested to roll back **above** the threshold and
  **not** below the min-sample count (`controller_test.go`). (See
  [ShopSwift](../showcase/05-shopswift-release-engineer.md).)

Both write **audit entries** — which is the next pillar.

---

## The audit chain: turning a log into evidence

Any system can write a log. The control plane writes a **hash-chained, tamper-evident** audit
trail (`server/control-plane/compliance/`): each entry carries the actor, action, resource and
a chain hash linking it to the previous entry. The console recomputes the chain on load and
refuses to display "verified" if a single row was edited or deleted.

The difference matters commercially: *a log* says "we recorded it"; *a verified chain* says
"and here's cryptographic proof nobody altered the record." That's what turns a kill-switch
flip or a data-processing change into **defensible evidence** for a post-incident review or an
audit (`compliance/audit.go`, `mem.go`, migration `012_audit_log.sql`).

Crucially, audit isn't a feature you switch on — it's *how every mutation is recorded*. The act
of documenting is itself tamper-evident.

---

## Multi-tenancy and isolation

Every record is scoped by `tenant_id`; cross-tenant reads are denied
(`tests/e2e_query_overview_test.go`). Each tenant has its own wrapped signing key under logical
isolation. This is what lets one deployment serve thousands of SME tenants safely — and it's
the boundary that the partner/MSSP console (`web/partner-console/`) rolls up *over*, read-only,
for managed-service providers.

---

## The business read

- **The registry-as-truth + signed-config-downstream pattern is the whole trust story.** It's
  why you can run a cheap, eventually-consistent data plane without ever letting it hold a
  secret or invent a policy.
- **The audit chain is a compliance *product*, not a checkbox.** "Every change is
  cryptographically provable" shortens security questionnaires and audit cycles — a concrete
  time-saving you can sell to the regulated buyer.
- **`build_hash` as a single identity is an underrated moat.** Because trust, compliance and
  analytics all key off the same signed build proof, the platform tells one coherent story
  about a release — something you only get if you *own all four planes* instead of stitching
  tools.

Next: [Chapter 7 — Privacy & compliance as features](07-privacy-and-compliance.md).
