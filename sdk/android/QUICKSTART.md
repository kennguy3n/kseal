# Get secure fast — Android (Kotlin)

Add server-decided app trust to an Android app in ~5 minutes. The SDK gathers
on-device signals and produces per-request proofs; the **server** makes the
trust decision (ALLOW / STEP_UP / DENY) — never the client.

> A complete, runnable version of everything below lives in
> [`examples/android`](../../examples/android). Clone it, set the four
> `KSEAL_*` properties, and `./gradlew :app:installDebug`.

## Requirements

- Android **7.0 (API 24)** or newer, NDK-built `arm64-v8a` / `armeabi-v7a` slices.
- A tenant + app provisioned on your kseal control plane (`tenantId`, `appId`,
  `apiKey`). Seed a local dev tenant with
  [`examples/backend-quickstart`](../../examples/backend-quickstart).

## 1. Depend on the AAR

```kotlin
// settings.gradle.kts → include the published io.kseal:sdk-android artifact,
// or composite-build this module during local development.
dependencies {
    implementation("io.kseal:sdk-android:<version>") // see CHANGELOG.md
}
```

## 2. Initialize once (no network at launch)

```kotlin
// Application.onCreate() or your DI graph — initialize is idempotent.
val sdk = KsealSDK.initialize(
    context = applicationContext,
    tenantId = "<tenant>",
    appId = "<app>",
    apiKey = "<api-key>",
    options = KsealOptions(buildHash = "sha256:<your-build-hash>"),
)
```

`KsealOptions` defaults keep the footprint small and launch network-free; the
only field most apps set is `buildHash` (emitted by the Gradle hardening
plugin). Run all probes by leaving `enabledProbes = null`.

## 3. Evaluate local risk (offline, cheap)

```kotlin
val risk = sdk.evaluateRisk()
// risk.trustLevel / risk.score / risk.isClean / risk.signals
```

## 4. Establish a trust session, then sign requests

Transport is yours (OkHttp/Retrofit). The flow is:

```
getNonce → <platform attestation> → verifyAttestation → setTrustToken
         → getRequestProof → validateRequestProof
```

```kotlin
val nonce = client.getNonce()                          // your transport
val token = playIntegrityToken(nonce)                  // Play Integrity API
val session = client.verifyAttestation(nonce, buildHash, instanceId, token)
if (!session.accepted) return                           // server fail-closed

sdk.setTrustToken(session.tokenId)
val proof = sdk.getRequestProof(sha256("POST /v1/orders"))
val decision = client.validateRequestProof(proof.proofBytes) // ALLOW/STEP_UP/DENY
```

React to `decision`: proceed on ALLOW, prompt MFA on STEP_UP, block on DENY.

## 5. Handle errors by type, not message

Every SDK failure is a [`KsealException`](src/main/kotlin/io/kseal/sdk/KsealException.kt)
carrying a typed [`KsealErrorCode`](src/main/kotlin/io/kseal/sdk/KsealException.kt):

```kotlin
try {
    val proof = sdk.getRequestProof(requestHash)
} catch (e: KsealException) {
    when (e.code) {
        KsealErrorCode.TRUST_TOKEN_MISSING -> establishTrustSession() // attest first
        KsealErrorCode.CONFIG_REJECTED     -> reportAndFallBack(e)
        else                               -> log(e)
    }
}
```

## Next steps

- Wire the [Gradle hardening plugin](../../plugins) to emit a real `buildHash`.
- Batch telemetry with `reportEvent(...)` / `flushTelemetry()`.
- Report transport-layer pinning failures via `reportPinningFailure()`.
