# Reference fixtures — the Meridian Pay canonical deployment

Every example in the kseal documentation draws from **one** coherent deployment so the
numbers, hashes, and payloads line up across the README, architecture, build guide, and
feature docs. The fixtures here are that deployment, captured as committed JSON. They are
not mock-ups: the crypto vectors are reproduced byte-for-byte by the Go server and the
Rust device core and asserted in CI, and the demo identifiers are plain `sha256` of a
documented input string so anyone can regenerate them.

## The customer

**Meridian Pay** — a payments company running kseal on two apps.

| Field | Value |
| --- | --- |
| Tenant | `meridian` |
| Apps | `pay-android` (consumer wallet), `merchant` (merchant terminal) |
| Regions | US, DE, BR, IN, SG |
| SIEM | Splunk (HEC) |
| Enforcement | `STEP_UP` (CRITICAL → deny, HIGH/MEDIUM → re-auth) |

## Reproducible identifiers

All three are a plain SHA-256 of the listed string (`printf '%s' "<input>" | sha256sum`):

| Identifier | Value (prefix) | Input string |
| --- | --- | --- |
| `build_hash` | `e3bb7952…a70d73` | `meridian/pay-android/1.4.0/seed=00000000` |
| `policy_hash` | `62fdc9b7…f508c34` | `meridian/payments-baseline/v12` |
| `install_key_hash` | `152c900d…731094f` | `meridian-demo-install-0001` |
| `coarse_time_bucket` | `1781582400` | `2026-06-16T04:00:00Z` (unix seconds, floored to the hour) |

## Layout

```
reference/fixtures/
├── trust/                     The trust handshake (device <-> control plane)
│   ├── get-nonce-response.json    32-byte single-use server nonce
│   ├── attestation-verdict.json   VerifyAttestation -> trust token (scenario D1, genuine)
│   ├── request-proof.json         Golden per-request proof HMAC (pinned in 4 places)
│   └── trust-decision.json        EvaluateTrust scoring walkthrough (scenario D3, CRITICAL)
├── events/                    Privacy-minimized telemetry leaving the device
│   ├── risk-event.json            One minimized event (scenario D5, remote-access)
│   └── telemetry-batch.json       The wire form (protobuf + zstd) and a decoded batch
├── egress/                    What partners receive
│   ├── webhook-body.json          The exact 524-byte signed webhook body (D3)
│   ├── webhook-delivery.json      The full HTTP request + HMAC signature recipe
│   └── siem-event.json            The same decision as a Splunk HEC event
├── control/                   Policy and remote control
│   ├── policy.json                Meridian's payments-baseline policy (v12)
│   ├── config-envelope.json       The signed ConfigResponse (policy + kill switch)
│   └── kill-switch-command.json   A REAL Ed25519-signed disable for a compromised build
├── scenarios.json             The 5 canonical device scenarios D1–D5, fully scored
└── golden-vectors.json        The cross-language crypto vectors that pin device<->server parity
```

## The five canonical scenarios

`scenarios.json` is the spine the feature docs reference. Each row is computed against the
real wire→server bit mapping and risk weights in `server/shared/risk`.

| ID | Situation | Server signals | Score | Trust level | Decision (STEP_UP mode) |
| --- | --- | --- | --- | --- | --- |
| D1 | Genuine install | — | 0 | TRUSTED | allow |
| D2 | Rooted device | root_jailbreak | 40 | LOW_RISK | allow |
| D3 | Repackaged build | app_tamper + attestation_fail | 130 | CRITICAL | **deny** |
| D4 | Overlay + accessibility abuse | overlay_abuse + accessibility_abuse | 75 | MEDIUM_RISK | step-up |
| D5 | Remote-access scam | screen_capture + accessibility_abuse + remote_access | 115 | HIGH_RISK | step-up |

## Verifying the fixtures

```bash
# Reproduce the demo identifiers
printf '%s' "meridian/pay-android/1.4.0/seed=00000000" | sha256sum   # build_hash

# Reproduce the webhook signature over the exact committed body
openssl dgst -sha256 -hmac 'whsec_meridian_demo_v1' egress/webhook-body.json

# The request-proof and kill-switch vectors are asserted in CI:
#   go test ./server/shared/proof/... ./server/shared/crypto/...
#   cargo test -p kseal-core
```
