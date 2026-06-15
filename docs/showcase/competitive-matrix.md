# Competitive positioning matrix

How kseal's demonstrated capabilities line up against top-tier players, viewed through the
lens of the **SME-at-scale, NoOps** segment (millions of MAU, no security team, no ops
budget). The point isn't that kseal beats every incumbent at the incumbent's specialty — it's
that kseal delivers the **whole job** in one product, zero-config, operable by one engineer.

Legend: **●** built-in / zero-config · **◑** present but requires config/analyst/integration ·
**○** not the product / DIY.

| Capability (with showcase evidence) | kseal | Approov | Guardsquare / Appdome / Promon | Castle / Arkose | Play Integrity / App Attest |
|---|:--:|:--:|:--:|:--:|:--:|
| Server-authoritative trust token bound to instance+build+risk+nonce+policy (`18`) | ● | ◑ | ○ | ○ | ○ (raw attestation only) |
| Fuse device signals **and** platform attestation server-side, with correct bit semantics (`15`) | ● | ◑ | ○ | ○ | ○ |
| Global decision stream + one-click risk triage in-product (`15`,`16`) | ● | ◑ | ○ | ◑ | ○ |
| **Fleet/population coordinated-abuse detection, zero-config** (`10`) | ● | ○ | ○ | ◑ (analyst-tuned) | ○ |
| Per-(build, region) cohort baselines + volume-velocity, O(1)/event (`10`) | ● | ○ | ○ | ◑ | ○ |
| Signed, client-verifiable remote kill switch (`05`,`06`) | ● | ◑ | ◑ | ○ | ○ |
| Hash-chained, **console-verified** audit trail (`08`,`13`) | ● | ○ | ○ | ◑ | ○ |
| Signed webhooks + SIEM with **named** signals & sealed secrets (`17`,`19`,`07`) | ● | ○ | ○ | ◑ | ○ |
| OWASP-MASVS coverage **derived from build proof** (`12`) | ● | ○ | ◑ (hardening reports) | ○ | ○ |
| In-product data-processing / retention registry (`11`) | ● | ○ | ○ | ○ | ○ |
| Canary rollout of trust policy + auto-rollback guardrail (`14`) | ● | ○ | ○ | ◑ | ○ |
| **Operable by one engineer, zero analysts/ops** | ● | ◑ | ◑ | ○ | ◑ |
| **One platform for the whole job** (attestation → fleet → response → compliance) | ● | ○ | ○ | ○ | ○ |

## Reading the matrix

- **Approov** is a credible server-side attestation peer, but it leaves fleet analytics, SIEM
  correlation, compliance evidence and staged policy rollout to the customer.
- **Guardsquare / Appdome / Promon** are app-hardening leaders (obfuscation, RASP). They make
  the app harder to attack; they are not the server-side trust-decision, fleet-analytics,
  response and compliance suite.
- **Castle / Arkose** are strong at population/behavioral abuse — genuinely a peer (or better)
  on that single axis — but they are account-abuse platforms that expect analyst tuning, not
  mobile-attestation + integrity + compliance suites.
- **Play Integrity / App Attest** are raw platform signals — an *input* to kseal, not a
  product that decides, detects fleets, responds, or proves compliance.

## The SME thesis in one line

> Each incumbent owns one column well. The SME needs the **whole row** — and can't afford to
> hire the team required to wire four products together. kseal's wedge is delivering the
> whole row, zero-config, at SME-at-scale economics (O(1)/event, bounded memory, aggregates-
> only, in-process).
