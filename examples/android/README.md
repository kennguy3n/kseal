# Android quickstart

A minimal Android app that integrates the kseal **Android SDK** end-to-end:

```
initialize → evaluateRisk → GetNonce → attestation → VerifyAttestation
           → setTrustToken → getRequestProof → ValidateRequestProof
```

The SDK is built from source via a Gradle **composite build**
(`includeBuild("../../sdk/android")`), so the sample always tracks the SDK on
`main`. The app follows the SDK's documented split: the SDK produces signals and
proofs; the **host owns transport** (here `KsealTrustClient`, OkHttp).

## Prerequisites

- Android Studio (or the Android SDK + NDK command-line tools). The kseal SDK
  builds a native Rust trust core, so the NDK and `cargo-ndk` are required —
  see [`sdk/android`](../../sdk/android) and `scripts/build-rust-android.sh`.
- A running server. From the repo root: `make docker-up`. The app defaults to
  `http://10.0.2.2:8080`, which is the host loopback as seen from the Android
  emulator.

## Configure

No code edits needed — pass Gradle properties (or set defaults in
`app/build.gradle.kts`):

| Property            | Default               | Meaning                                  |
|---------------------|-----------------------|------------------------------------------|
| `ksealTenant`       | `acme`                | Tenant id                                |
| `ksealApp`          | `com.acme.app`        | App id                                   |
| `ksealApiKey`       | *(empty)*             | Control-plane API key (optional here)    |
| `ksealEndpoint`     | `http://10.0.2.2:8080`| Server base URL                          |
| `ksealGcpProject`   | `0`                   | Google Cloud project number for Play Integrity; `0` uses the dev provider |

Provision a matching tenant/app with the
[backend quickstart](../backend-quickstart) seeder and pass the same ids.

## Build & run

```bash
cd examples/android
./gradlew :app:installDebug      # or open in Android Studio and Run
```

Tap **Run trust flow**; the output panel shows each stage and the final
ALLOW / STEP_UP / DENY decision.

## What's real vs. mocked

- **Real:** SDK init, the native RASP probes, risk scoring in the Rust core over
  JNI, nonce binding, the request-proof HMAC, and the three `TrustService` RPCs.
- **Mocked:** only the **external** attestation provider.
  `PlayIntegrityTokenProvider` is the real default (set `ksealGcpProject`);
  `DevAttestationTokenProvider` lets you exercise the plumbing offline.

`VerifyAttestation` is **fail-closed**: without a real Google-signed Play
Integrity verdict a stock server rejects the session, which the app reports.
For a fully runnable chain with the provider mocked at the server's JWKS source
(the documented test path), see the
[backend quickstart](../backend-quickstart).
