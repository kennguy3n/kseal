# Get secure fast — iOS (Swift)

Add server-decided app trust to an iOS app in ~5 minutes. The SDK gathers
on-device signals and produces per-request proofs; the **server** makes the
trust decision (ALLOW / STEP_UP / DENY) — never the client. The SDK uses **no
private/undocumented APIs**, so it stays App Review safe.

> A complete, runnable version lives in
> [`examples/ios-quickstart`](../../examples/ios-quickstart)
> (`swift run kseal-ios-quickstart`).

## Requirements

- iOS **13** or newer (the package also builds for macOS 11+ for host testing).
- A tenant + app provisioned on your kseal control plane (`tenantId`, `appId`,
  `apiKey`). Seed a local dev tenant with
  [`examples/backend-quickstart`](../../examples/backend-quickstart).

## 1. Add the package

```swift
// Package.swift
.package(url: "https://github.com/kennguy3n/kseal.git", from: "<version>"),
// target dependency: .product(name: "KsealSDK", package: "kseal")
```

See [CHANGELOG.md](CHANGELOG.md) for versions.

## 2. Initialize once (no network at launch)

```swift
import KsealSDK

let sdk = try KsealSDK.initialize(
    tenantId: "<tenant>",
    appId: "<app>",
    apiKey: "<api-key>",
    options: KsealOptions(buildHash: "sha256:<your-build-hash>")
)
```

`initialize` is idempotent; call it once at launch. Defaults keep the binary
slice small and launch network-free.

## 3. Evaluate local risk (offline, cheap)

```swift
let risk = try sdk.evaluateRisk()
// risk.trustLevel / risk.score / risk.isClean / risk.signals
```

## 4. Establish a trust session, then sign requests

Transport is yours (`URLSession`). The flow is:

```
getNonce → App Attest/DeviceCheck → verifyAttestation → setTrustToken
         → getRequestProof → validateRequestProof
```

```swift
let nonce = try await client.getNonce()                 // your transport
let token = try await appAttestToken(for: nonce)        // App Attest
let session = try await client.verifyAttestation(nonce: nonce, buildHash: buildHash,
                                                 instanceId: instanceId, token: token)
guard session.accepted else { return }                  // server fail-closed

sdk.setTrustToken(session.tokenId)
let proof = try sdk.getRequestProof(requestHash: sha256("POST /v1/orders"))
let decision = try await client.validateRequestProof(proof.proofBytes) // ALLOW/STEP_UP/DENY
```

React to `decision`: proceed on ALLOW, prompt MFA on STEP_UP, block on DENY.

## 5. Handle errors by type, not message

Every SDK failure is a [`TrustCoreError`](Sources/KsealSDK/TrustCore.swift)
carrying a typed [`KsealErrorKind`](Sources/KsealSDK/TrustCore.swift):

```swift
do {
    let proof = try sdk.getRequestProof(requestHash: requestHash)
} catch let error as TrustCoreError {
    switch error.kind {
    case .trustTokenMissing: try await establishTrustSession() // attest first
    case .configRejected:    reportAndFallBack(error)
    default:                 log(error)
    }
}
```

`TrustCoreError` conforms to `LocalizedError`, so `error.localizedDescription`
is always populated for logs (never with PII).

## Next steps

- Wire the [Xcode hardening plugin](../../plugins) to emit a real `buildHash`.
- Batch telemetry with `reportEvent(_:)` / `flushTelemetry()`.
- Report transport-layer pinning failures via `reportPinningFailure()`.
