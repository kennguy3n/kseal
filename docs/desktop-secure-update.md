# kseal — Desktop secure-update verification

A self-updating desktop app is a high-value supply-chain target: if the update
channel is not cryptographically verified, a tampered feed or a man-in-the-middle
is **remote code execution with the app's privileges**. This module gives the
[desktop SDK](desktop-sdk.md) a real, productized **verify-before-apply** gate
for both macOS and Windows that **fails closed** on any verification failure.

It does **not** download or install anything itself — the host keeps its own
updater/transport. The SDK's job is the security-critical part: given a feed and
an archive, decide whether the bytes are an authentic, newer, runnable release.

- macOS: `SecureUpdateChannel` in [`sdk/desktop/macos`](../sdk/desktop/macos) —
  Sparkle-style signed appcast.
- Windows: `SecureUpdateChannel` in [`sdk/desktop/windows`](../sdk/desktop/windows) —
  Ed25519-signed manifest + optional Authenticode payload check.

## Table of contents

- [Threat model & guarantees](#threat-model--guarantees)
- [Verification pipeline](#verification-pipeline)
- [macOS — Sparkle signed appcast](#macos--sparkle-signed-appcast)
- [Windows — signed manifest + Authenticode](#windows--signed-manifest--authenticode)
- [Mock boundary](#mock-boundary)
- [Fail-closed matrix](#fail-closed-matrix)
- [Operating the channel (key custody)](#operating-the-channel-key-custody)
- [Validation](#validation)

## Threat model & guarantees

The adversary can fully control the network and the update feed: serve arbitrary
manifests, swap archives, replay or downgrade, strip signatures. They do **not**
have the channel's Ed25519 **private** key (held by the release pipeline, never
on the device) nor the publisher's code-signing key.

Guarantees the channel enforces before returning an `updateAvailable`:

1. **Authenticity & integrity** — the archive bytes carry a valid **Ed25519
   (EdDSA)** signature under the channel's public key. This is the *same*
   cryptographic primitive (and the *same Rust-core verifier over the C FFI*)
   used to verify signed tenant config, so there is one audited signature path,
   not a second bespoke one.
2. **No downgrade** — only a version **strictly newer** than the running version
   is offered (numeric, component-wise ordering, so `1.10.0 > 1.9.0`).
3. **Runnability** — an item's minimum-OS gate must be satisfied by the current
   OS, else it is skipped (and the next-newest runnable item is considered).
4. **Size match** — the downloaded archive length must equal the length declared
   in the (signed) feed, catching truncation/substitution early.
5. **Platform packaging** (opt-in) — macOS notarization / Windows Authenticode of
   the payload, when the channel policy requires it.

**Fail-closed is absolute for cryptographic failures**: a bad/missing signature,
a length mismatch, a failed notarization/Authenticode check, or an invalid
channel key all `throw` — the channel *never* returns an update it could not
fully verify. A *network/parse* failure (unreachable feed, malformed XML/JSON) is
treated as **"no update available"** so a flaky feed degrades to "stay on the
current, known-good build" rather than blocking or, worse, applying junk.

## Verification pipeline

Both platforms implement the identical decision pipeline; only the feed format
and the optional packaging check differ.

```
fetch feed ──▶ filter: version > current ──▶ filter: OS can run item
   │                                                     │
   │                                            pick newest remaining
   ▼                                                     ▼
 parse error ⇒ "no update"                    fetch archive bytes
                                                         │
                              ┌──────────────────────────┤
                              ▼                           ▼
                    length == declared?         Ed25519 verify(archive)
                       no ⇒ THROW                  invalid ⇒ THROW
                              │                           │
                              └────────────┬──────────────┘
                                           ▼
                         policy.requireNotarization/Authenticode?
                                  fails ⇒ THROW
                                           ▼
                                  updateAvailable(verified)
```

The channel public key must be exactly **32 bytes** (Ed25519); anything else is
rejected up front (`invalidChannelKey`) rather than silently failing later.

## macOS — Sparkle signed appcast

macOS apps overwhelmingly update via **Sparkle**, whose appcast is an RSS feed
with `<sparkle:edSignature>` (Ed25519 over the archive) and
`sparkle:length`/`sparkle:version` attributes. `AppcastParser` is a
namespace-aware `XMLParser` reader that is deliberately strict: an item missing
any required field (version, url, length, signature) is **silently skipped**, and
a malformed document throws `malformedFeed` (⇒ "no update"). Notarization is an
opt-in check behind the `UpdateNotaryVerifier` seam (a production impl runs a
Gatekeeper `SecAssessment`; tests use a fake).

```swift
let channel = SecureUpdateChannel(
    policy: .init(
        publicKey: appcastPublicKey,           // Ed25519, 32 bytes
        currentVersion: .init("1.4.0"),
        currentSystemVersion: .init("14.5.0"), // honor minimumSystemVersion gates
        requireNotarization: true),
    feed: myAppcastFeed)                        // your transport behind AppcastFeed

switch try channel.checkForUpdate() {
case .upToDate:
    break
case .updateAvailable(let verified):
    // verified.archive: signature + length + notarization already checked.
    apply(verified.archive)
}
```

Example appcast item the parser accepts:

```xml
<item>
  <sparkle:version>2.0.0</sparkle:version>
  <sparkle:minimumSystemVersion>13.0.0</sparkle:minimumSystemVersion>
  <enclosure url="https://updates.example/App-2.0.0.zip"
             sparkle:edSignature="<base64 Ed25519 signature of the archive bytes>"
             length="10485760" />
</item>
```

## Windows — signed manifest + Authenticode

Windows has no single canonical appcast, so the channel consumes a compact
**Ed25519-signed JSON manifest** (same signature semantics as macOS) and adds an
**Authenticode** check of the downloaded payload — the Windows-native trust
anchor for executables/installers — behind the `IUpdatePackageVerifier` seam. A
production verifier runs `WinVerifyTrust` on the payload and matches the expected
publisher; tests use a fake.

```csharp
var channel = new SecureUpdateChannel(
    new UpdateChannelPolicy
    {
        PublicKey = updatePublicKey,                  // Ed25519, 32 bytes
        CurrentVersion = new UpdateVersion("1.4.0"),
        CurrentOsVersion = new UpdateVersion("10.0.22631"),
        RequireAuthenticode = true,                   // verify the payload's Authenticode too
    },
    myUpdateFeed);                                    // your transport behind IUpdateFeed

switch (channel.CheckForUpdate())
{
    case SecureUpdateResult.UpToDate:
        break;
    case SecureUpdateResult.UpdateAvailable a:
        Apply(a.Update.Archive);                      // already fully verified
        break;
}
```

Manifest format:

```json
{
  "items": [
    {
      "version": "2.0.0",
      "url": "https://updates.example/App-2.0.0.msi",
      "length": 10485760,
      "edSignature": "<base64 Ed25519 signature of the archive bytes>",
      "minimumOsVersion": "10.0.19041"
    }
  ]
}
```

A field that fails to decode (e.g. a non-base64 `edSignature`) causes the item to
be skipped rather than trusted; malformed JSON throws `MalformedFeed` (⇒ "no
update").

## Mock boundary

Per the engineering rules, **only the external third-party services are mocked**;
all verification logic is real and unit-tested.

| Concern | Interface (seam) | Real default / production | Test fake |
|---|---|---|---|
| Update feed (network) | `AppcastFeed` / `IUpdateFeed` | host transport (HTTPS manifest + CDN archive) | `InMemoryAppcastFeed` / `InMemoryUpdateFeed` |
| Ed25519 verification | `UpdateSignatureVerifier` | **Rust core over the C FFI** (real) | — (always real in tests) |
| Notarization / Authenticode | `UpdateNotaryVerifier` / `IUpdatePackageVerifier` | Gatekeeper `SecAssessment` / `WinVerifyTrust` | permissive + denying fakes |

The signature check is **never** mocked — tests verify against the real Ed25519
implementation in the core using fixed test vectors signed by a known key, so a
regression in the verification path fails the suite.

## Fail-closed matrix

| Condition | macOS error | Windows error | Result |
|---|---|---|---|
| Channel key not 32 bytes | `invalidChannelKey` | `InvalidChannelKey` | **throw** |
| Feed unparseable | `malformedFeed` | `MalformedFeed` | **throw** (host treats as "no update") |
| Item missing a required field | — | — | item skipped |
| Archive length ≠ declared | `lengthMismatch` | `LengthMismatch` | **throw** |
| Signature invalid / wrong key / tampered archive | `signatureInvalid` | `SignatureInvalid` | **throw** |
| Notarization/Authenticode required but fails | `notarizationFailed` | `AuthenticodeInvalid` | **throw** |
| No newer (or no runnable) version | — | — | `upToDate` |
| All checks pass | — | — | `updateAvailable` |

## Operating the channel (key custody)

- The channel **private key never touches the device**. Signing happens in the
  release pipeline (ideally an HSM/KMS or an offline signer); only the **public**
  key is shipped/pinned in the app, exactly like the tenant config-signing key.
- Rotating the channel key is a client update (ship the new public key in a
  release signed by the old key), so rotation is itself gated by the chain of
  trust.
- Treat the Ed25519 signature as the authority and Authenticode/notarization as
  defense-in-depth for the OS packaging layer — require them for production
  channels.
- The check is **off the hot path** and performs no network in the SDK itself, so
  it fits the desktop performance/footprint budget; the host decides when to poll.

## Validation

Verification is exercised against the **real** Ed25519 verifier in the Rust core
over the C FFI, with fixed test vectors signed by a known key:

- macOS: `SecureUpdateTests` (Swift/XCTest) — version ordering, appcast parsing,
  item-skipping, newest-selection + valid signature, minimum-OS gating, up-to-date,
  tampered-archive, length-mismatch, notarization required/missing/present,
  invalid + wrong channel key.
- Windows: `SecureUpdateTests` (xUnit) — the same matrix, plus Authenticode
  required/missing/present via the `IUpdatePackageVerifier` fake.

See the [Validation summary](desktop-sdk.md#validation-summary) in the desktop SDK
doc for the full counts.
