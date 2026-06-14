# Get secure fast — macOS (Swift)

Add server-decided app trust to a macOS app in ~5 minutes. The SDK verifies the
running app's code signature, gathers integrity signals, and produces
per-request proofs bound to a hardware-backed key; the **server** makes the
trust decision (ALLOW / STEP_UP / DENY). Uses only Gatekeeper-safe public APIs.

> A complete, runnable version lives in
> [`examples/desktop-macos`](../../../examples/desktop-macos)
> (`swift run kseal-desktop-quickstart`).

## Requirements

- macOS **11 (Big Sur)** or newer.
- A tenant + app provisioned on your kseal control plane (`tenantId`, `appId`).
  Seed a local dev tenant with
  [`examples/backend-quickstart`](../../../examples/backend-quickstart).

## 1. Add the package

```swift
// Package.swift
.package(url: "https://github.com/kennguy3n/kseal.git", from: "<version>"),
// target dependency: .product(name: "KsealDesktop", package: "kseal")
```

See [CHANGELOG.md](CHANGELOG.md) for versions.

## 2. Initialize once (no network at launch)

```swift
import KsealDesktop

let sdk = try KsealDesktop.initialize(
    tenantId: "<tenant>",
    appId: "<app>",
    options: KsealDesktopOptions(buildHash: "sha256:<your-build-hash>")
)
```

The proof key is bound to the Secure Enclave / hardware key store when
available, falling back to file storage otherwise. Initialization performs no
network I/O.

## 3. Evaluate local risk (offline, cheap)

```swift
let risk = try sdk.evaluateRisk()
// risk.trustLevel / risk.score / risk.isClean / risk.signals
```

## 4. Establish a trust session, then sign requests

The desktop SDK drives the whole handshake for you given a `TrustSessionClient`
(your transport): `establishTrustSession` runs
`getNonce → attest → verifyAttestation → setTrustToken` and stores the token.

```swift
let session = try sdk.establishTrustSession(using: client)
guard session.accepted else { return }                 // server fail-closed

// Sign a protected request and let the server decide in one call:
let decision = try sdk.authorizeRequest(requestHash: sha256("POST /v1/orders"),
                                        using: client)  // ALLOW / STEP_UP / DENY
```

Prefer the lower-level `getRequestProof(requestHash:)` if you own the validate
round-trip yourself. React to `decision`: proceed on ALLOW, prompt MFA on
STEP_UP, block on DENY.

## 5. Handle errors by type, not message

Every SDK failure is a [`TrustCoreError`](Sources/KsealDesktop/TrustCore.swift)
carrying a typed [`KsealErrorKind`](Sources/KsealDesktop/TrustCore.swift):

```swift
do {
    let decision = try sdk.authorizeRequest(requestHash: hash, using: client)
} catch let error as TrustCoreError {
    switch error.kind {
    case .trustTokenMissing: _ = try sdk.establishTrustSession(using: client)
    case .configRejected:    reportAndFallBack(error)
    default:                 log(error)
    }
}
```

## Next steps

- Supply an `EnterprisePolicy` via `KsealDesktopOptions` for MDM-managed fleets.
- Batch telemetry with `reportEvent(_:)` / `flushTelemetry()`.
