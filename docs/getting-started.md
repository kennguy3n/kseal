# Getting Started with kseal

A hands-on guide to building the iOS and Android sample apps, running the full
trust flow, and understanding what kseal does. Every step below has been verified
on macOS with Apple Silicon (June 2025).

---

## Table of Contents

- [What You'll Build](#what-youll-build)
- [Prerequisites](#prerequisites)
- [Step 1 — Build the Rust Trust Core](#step-1--build-the-rust-trust-core)
- [Step 2 — Build & Run the iOS Quickstart](#step-2--build--run-the-ios-quickstart)
- [Step 3 — Build the Android Quickstart](#step-3--build-the-android-quickstart)
- [Step 4 — Run the Backend Quickstart (Full Trust Flow)](#step-4--run-the-backend-quickstart-full-trust-flow)
- [Step 5 — Run the Test Suite](#step-5--run-the-test-suite)
- [Understanding the Trust Flow](#understanding-the-trust-flow)
- [kseal Capabilities Demonstrated](#kseal-capabilities-demonstrated)
- [Troubleshooting](#troubleshooting)

---

## What You'll Build

Both sample apps demonstrate the full kseal device-plane SDK surface:

```
initialize → coreVersion → evaluateRisk → evaluateTrustDecision
           → onTrustDecision / onKillSwitchChanged hooks
           → reportEvent → reportPinningFailure → flushTelemetry
           → isKilled → refreshConfig → startContinuousProtection → onAppForeground
           → GetNonce → attestation → VerifyAttestation
           → setTrustToken → getRequestProof → ValidateRequestProof
           → stopContinuousProtection
```

The SDK gathers on-device signals and produces per-request proofs. The
**server** makes the trust decision (ALLOW / STEP_UP / DENY) — never the client.

| Sample | Language | Location | Build command |
|--------|----------|----------|---------------|
| iOS | Swift | `examples/ios-quickstart` | `swift run kseal-ios-quickstart` |
| Android | Kotlin | `examples/android` | `./gradlew :app:assembleDebug` |
| Backend (full flow) | Go | `examples/backend-quickstart` | `go run .` |

---

## Prerequisites

### Common (all platforms)

| Tool | Install |
|------|---------|
| **Rust** 1.74+ | `curl https://sh.rustup.rs -sSf \| sh` |
| **protobuf** | `brew install protobuf` |
| **Go** 1.25+ | `brew install go` (for backend quickstart) |

### iOS only

| Tool | Install |
|------|---------|
| **Swift** 5.9+ | Xcode Command Line Tools: `xcode-select --install` |

### Android only

| Tool | Install |
|------|---------|
| **JDK 17** | `brew install --cask temurin@17` |
| **Android SDK** | `brew install --cask android-commandlinetools` |
| **cargo-ndk** | `cargo install cargo-ndk` |
| **Rust Android targets** | `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` |

After installing the Android SDK, set environment variables (add to
`~/.zshrc` or `~/.bashrc`):

```bash
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
export ANDROID_HOME="/opt/homebrew/share/android-commandlinetools"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.1.10909125"
```

Then install the SDK components:

```bash
yes | sdkmanager --sdk_root="$ANDROID_HOME" \
  "platforms;android-34" "build-tools;34.0.0" "platform-tools" "ndk;26.1.10909125"
```

---

## Step 1 — Build the Rust Trust Core

The Rust trust core (`kseal-ffi`) is shared by both the iOS and Android SDKs.
Build it once before building either sample.

```bash
cargo build --manifest-path sdk/rust-core/Cargo.toml -p kseal-ffi
```

This produces:
- `sdk/rust-core/target/debug/libkseal_ffi.a` — static library linked by the iOS SDK
- `sdk/rust-core/kseal-ffi/include/kseal.h` — C header (cbindgen-generated)

### Stage the header for iOS

The iOS SDK's `CKseal` target expects `kseal.h` in its include directory. Run
the staging script:

```bash
bash sdk/ios/scripts/build-rust-host.sh
```

### Cross-compile for Android ABIs

The Android SDK needs `.so` files per ABI. Run:

```bash
bash sdk/android/scripts/build-rust-android.sh
```

This produces `libkseal_ffi.so` for `arm64-v8a`, `armeabi-v7a`, and `x86_64`
under `sdk/android/src/main/jniLibs/`.

---

## Step 2 — Build & Run the iOS Quickstart

```bash
cd examples/ios-quickstart
swift build
swift run kseal-ios-quickstart
```

### Expected output (without server)

```
kseal iOS quickstart — tenant=acme app=com.acme.app endpoint=http://localhost:8080
[core] version=0.1.0
[risk] trustLevel=unspecified score=10 clean=false signals=1
       signal: jailbreak
[decision] level=unspecified decision=allow
[telemetry] queued 3 events (tamper, debugger, pinning-failure)
[kill-switch] isKilled=false
[config] loaded=false
[continuous] started=false (requires policy with reattest_interval_secs > 0)
[hook] onTrustDecision: level=unspecified decision=allow
[reattest] onAppForeground cycle triggered
[trust] TrustService/GetNonce failed (500): {"code":"internal","message":"ERROR: invalid input syntax for type uuid: \"com.acme.app\" (SQLSTATE 22P02)"}
start the server with `make docker-up`, then re-run.
[telemetry] flushed
done.
```

The on-device features (risk evaluation, trust decision, telemetry, kill
switch, config, continuous protection, re-attestation) all run without a server.
Only the trust flow (GetNonce → VerifyAttestation) needs a running server; see
[Step 4](#step-4--run-the-backend-quickstart-full-trust-flow).

### Expected output (with server running)

After starting the server and seeding a tenant (see
[Step 4](#step-4--run-the-backend-quickstart-full-trust-flow)), run with the
seeded environment variables:

```bash
eval "$(cd ../backend-quickstart && go run . -seed)"
swift run kseal-ios-quickstart
```

```
kseal iOS quickstart — tenant=<uuid> app=<uuid> endpoint=http://localhost:8080
[core] version=0.1.0
[risk] trustLevel=unspecified score=10 clean=false signals=1
       signal: jailbreak
[decision] level=unspecified decision=allow
[telemetry] queued 3 events (tamper, debugger, pinning-failure)
[kill-switch] isKilled=false
[config] loaded=false
[continuous] started=false (requires policy with reattest_interval_secs > 0)
[hook] onTrustDecision: level=unspecified decision=allow
[reattest] onAppForeground cycle triggered
[nonce] 32 bytes
[trust] rejected: cbor decode: cbor: 55 bytes of extraneous data starting at index 5
        expected with the dev attestation provider; use App Attest on a real device.
[telemetry] flushed
done.
```

With the server running, `GetNonce` succeeds (32 bytes). The attestation is
still rejected because `DevAttestationTokenProvider` returns a placeholder — the
server is fail-closed. To complete the full trust flow locally, use the
[backend quickstart](#step-4--run-the-backend-quickstart-full-trust-flow).

### Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `KSEAL_TENANT` | `acme` | Tenant id |
| `KSEAL_APP` | `com.acme.app` | App id |
| `KSEAL_API_KEY` | *(empty)* | Control-plane API key |
| `KSEAL_ENDPOINT` | `http://localhost:8080` | Server base URL |

```bash
KSEAL_TENANT=my-tenant KSEAL_ENDPOINT=http://localhost:8080 swift run kseal-ios-quickstart
```

### SDK features demonstrated

| Feature | API | Needs server? |
|---------|-----|---------------|
| Core version | `sdk.coreVersion` | No |
| Risk evaluation (RASP probes) | `sdk.evaluateRisk()` | No |
| Trust decision (local) | `sdk.evaluateTrustDecision()` | No |
| Active-response hook | `sdk.onTrustDecision` | No |
| Kill-switch hook | `sdk.onKillSwitchChanged` | No |
| Telemetry events | `sdk.reportEvent()` | No |
| Pinning failure report | `sdk.reportPinningFailure()` | No |
| Flush telemetry | `sdk.flushTelemetry()` | No |
| Kill switch state | `sdk.isKilled` | No |
| Config refresh | `sdk.refreshConfig()` | No (no-op without provider) |
| Continuous protection | `sdk.startContinuousProtection()` | No (no-op without policy) |
| Re-attestation cycle | `sdk.onAppForeground()` | No |
| Stop continuous protection | `sdk.stopContinuousProtection()` | No |
| GetNonce | `client.getNonce()` | Yes |
| VerifyAttestation | `client.verifyAttestation()` | Yes |
| ValidateRequestProof | `client.validateRequestProof()` | Yes |

### What's real vs. mocked

- **Real:** SDK init, native RASP probes (debugger/hook detection via `sysctl`
  and dyld image scanning), risk scoring in the Rust core, trust decision
  evaluation, telemetry event creation and batching, pinning failure reporting,
  kill switch state, config refresh, continuous protection, re-attestation
  cycles, nonce binding, the request-proof HMAC, and all three `TrustService`
  RPCs.
- **Mocked:** only the external attestation provider. Apple App Attest /
  DeviceCheck runs only on a real device, so `DevAttestationTokenProvider`
  returns a placeholder for host runs. On-device, implement
  `AttestationTokenProvider` with `DCAppAttestService`.

---

## Step 3 — Build the Android Quickstart

### Cross-compile the Rust trust core for Android

```bash
bash sdk/android/scripts/build-rust-android.sh
```

### Build the APK

```bash
cd examples/android
./gradlew :app:assembleDebug
```

The APK is produced at:

```
examples/android/app/build/outputs/apk/debug/app-debug.apk
```

### Install on a device/emulator

```bash
./gradlew :app:installDebug
```

Or open `examples/android` in Android Studio and press Run.

### Using the app

Install on an emulator or device, then tap **Run trust flow**. The output panel
shows each stage. The on-device features (core version, risk evaluation, trust
decision, telemetry, kill switch, config, continuous protection, re-attestation)
work without a server. The trust flow (GetNonce → VerifyAttestation) needs a
running server — start it with `make docker-up` from the repo root first.

**Without a server**, the output shows the on-device features then a connection
error:

```
[core] version=0.1.0
[risk] trustLevel=UNSPECIFIED score=10 clean=false signals=1
[decision] level=UNSPECIFIED decision=ALLOW
[telemetry] queued 3 events (tamper, debugger, pinning-failure)
[kill-switch] isKilled=false
[config] loaded=false
[continuous] started=false (requires policy with reattest_interval_secs > 0)
[hook] onTrustDecision: level=UNSPECIFIED decision=ALLOW
[reattest] onAppForeground cycle triggered
[error] failed to connect to /10.0.2.2:8080
```

**With a server running** (and the dev attestation provider), `GetNonce`
succeeds but `VerifyAttestation` is rejected — the dev provider returns a
placeholder, not a real Play Integrity verdict:

```
[nonce] 32 bytes
[trust] rejected: jws verification failed: token malformed
        expected with the dev attestation provider; set -PksealGcpProject=<n> for real Play Integrity.
[telemetry] flushed
```

> **Note:** The Android expected output above is inferred from the code and the
> iOS quickstart behavior. The APK build is verified; running on an emulator
> requires an Android emulator/device.

To use real Play Integrity, pass your Google Cloud project number:

```bash
./gradlew :app:installDebug -PksealGcpProject=123456789012
```

### Configuration

| Property | Default | Meaning |
|----------|---------|---------|
| `ksealTenant` | `acme` | Tenant id |
| `ksealApp` | `com.acme.app` | App id |
| `ksealApiKey` | *(empty)* | Control-plane API key |
| `ksealEndpoint` | `http://10.0.2.2:8080` | Server URL (emulator's host loopback) |
| `ksealGcpProject` | `0` | Google Cloud project number; `0` uses the dev provider |

### SDK features demonstrated

Same as the iOS quickstart — see the [iOS SDK features table](#sdk-features-demonstrated).
Both apps exercise the identical SDK API surface.

### What's real vs. mocked

- **Real:** SDK init, native RASP probes (debugger detection via `/proc/self/status`,
  hook/Frida detection via `/proc/self/maps` and thread-name scanning), risk
  scoring in the Rust core over JNI, trust decision evaluation, telemetry event
  creation and batching, pinning failure reporting, kill switch state, config
  refresh, continuous protection, re-attestation cycles, nonce binding, the
  request-proof HMAC, and all three `TrustService` RPCs.
- **Mocked:** only the external Play Integrity provider.
  `PlayIntegrityTokenProvider` is the real default (set `ksealGcpProject`);
  `DevAttestationTokenProvider` exercises the plumbing offline.

---

## Step 4 — Run the Backend Quickstart (Full Trust Flow)

The backend quickstart is the one that runs the **complete** attestation →
token → proof chain locally. It swaps the server's Play Integrity JWKS source
for a locally generated RSA key (the documented test path), so no real Google or
Apple attestation is needed.

### Start the server stack

```bash
make docker-up        # server :8080 + Postgres :5432 + Redis :6379 + dashboard :5173
```

Verify it's up:

```bash
curl -fsS localhost:8080/healthz
curl -fsS localhost:8080/readyz
```

### Run the in-process demo

```bash
cd examples/backend-quickstart
go run .
```

### Expected output

Verified output from `go run .` against a live `make docker-up` server:

```
[1] Seed a tenant, app, build, active policy, and a control-plane API key
    tenant_id = 2e41029a-5f9b-4463-8bc4-b1b239d848fe
    app_id    = 02e0be1c-e0d8-4e70-a916-35805c30bd90 (com.kseal.quickstart)
    build     = sha256:0000000000000000000000000000000000000000000000000000000000000001
    api_key   = ksk_b146d1d15bc09dfa__BvUjeB4vU6tZXagerHUoafU-WEiA6_Y   (control-plane: send as `Authorization: Bearer <key>`)

[2] Device plane: GetNonce -> VerifyAttestation -> ValidateRequestProof
    clean device -> trust level TRUSTED, token 52743083…
    request proof (seq=1) decision: ALLOW
    replayed proof (seq=1) decision: DENY  (anti-replay)

[3] A risky device steps up / is denied by the SAME policy (server-authoritative)
    tampered/unrecognized device -> trust level CRITICAL, decision DENY

[4] QueryService read: tenant overview + trust-session stats
    apps=1 builds=1 active_policies=1
    trust sessions: total=2 tokens_issued=2 attestations_failed=0 by_level=map[CRITICAL:1 TRUSTED:1]

Done. See README.md for the equivalent curl walkthrough against a live `make docker-up` server.
```

> The tenant_id, app_id, and api_key values are generated fresh each run.

This demonstrates:
- A **clean device** gets `ALLOW`
- A **replayed proof** gets `DENY` (anti-replay via monotonic sequence)
- A **tampered device** gets `DENY` (server-authoritative risk scoring)

### Seed a tenant for the mobile samples

```bash
cd examples/backend-quickstart
eval "$(go run . -seed)"
# exports KSEAL_TENANT, KSEAL_APP, KSEAL_API_KEY
```

Verified output:

```
KSEAL_TENANT=5c8296ab-006f-41ea-9d27-3bd410a6f4c7
KSEAL_APP=5de7df5d-8992-4483-a5ec-080187f2e3b5
KSEAL_API_KEY=ksk_021c731e1e23e55b_sg-oH0GrPZwktGrssKcTIgpDeRtoNva4
```

> The UUIDs and API key are generated fresh each run.

Then re-run the iOS sample with those environment variables:

```bash
cd examples/ios-quickstart
swift run kseal-ios-quickstart
```

For Android, pass the values as Gradle properties:

```bash
cd examples/android
./gradlew :app:installDebug -PksealTenant=<uuid> -PksealApp=<uuid> -PksealApiKey=ksk_...
```

---

## Step 5 — Run the Test Suite

### Server tests (Go)

```bash
cd server && go test ./...
```

Verified output (25 packages, all pass):

```
ok      github.com/kennguy3n/kseal/server/cmd/kseal-server              6.979s
ok      github.com/kennguy3n/kseal/server/control-plane/compliance      4.628s
ok      github.com/kennguy3n/kseal/server/control-plane/migrations      5.759s
ok      github.com/kennguy3n/kseal/server/control-plane/registry        2.598s
ok      github.com/kennguy3n/kseal/server/data-plane/attestation        6.475s
ok      github.com/kennguy3n/kseal/server/data-plane/canary            11.150s
ok      github.com/kennguy3n/kseal/server/data-plane/config             8.080s
ok      github.com/kennguy3n/kseal/server/data-plane/fleet             11.715s
ok      github.com/kennguy3n/kseal/server/data-plane/guardrails         7.513s
ok      github.com/kennguy3n/kseal/server/data-plane/ingest             8.979s
ok      github.com/kennguy3n/kseal/server/data-plane/query              9.964s
ok      github.com/kennguy3n/kseal/server/data-plane/siem               9.475s
ok      github.com/kennguy3n/kseal/server/data-plane/simulator          3.193s
ok      github.com/kennguy3n/kseal/server/data-plane/trust             10.646s
ok      github.com/kennguy3n/kseal/server/data-plane/webhook            9.830s
ok      github.com/kennguy3n/kseal/server/shared/auth                   9.684s
ok      github.com/kennguy3n/kseal/server/shared/config                 8.766s
ok      github.com/kennguy3n/kseal/server/shared/crypto                 8.201s
ok      github.com/kennguy3n/kseal/server/shared/db                     8.014s
ok      github.com/kennguy3n/kseal/server/shared/middleware             8.178s
ok      github.com/kennguy3n/kseal/server/shared/proof                  8.164s
ok      github.com/kennguy3n/kseal/server/shared/risk                   8.143s
ok      github.com/kennguy3n/kseal/server/shared/safehttp               7.801s
ok      github.com/kennguy3n/kseal/server/shared/telemetry              7.911s
```

### Rust core tests

```bash
cd sdk/rust-core && cargo test
```

Verified output (106 tests, all pass):

```
     Running unittests src/lib.rs (kseal_core)
test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running tests/integration.rs
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running unittests src/lib.rs (kseal_ffi)
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Trust service tests (VerifyAttestation + ValidateRequestProof)

```bash
cd server && go test ./data-plane/trust/... -v -count=1
```

Key tests:

| Test | What it verifies |
|------|-----------------|
| `TestTrustFlowEndToEnd` | Full GetNonce → VerifyAttestation → ValidateRequestProof lifecycle |
| `TestVerifyAttestationRejectsConsumedNonce` | Rejects with an invalid/unissued nonce |
| `TestVerifyAttestationRejectsFailedAttestation` | Does not mint a token on failed attestation |
| `TestVerifyAttestationRejectsUnknownApp` | Rejects when tenant/app doesn't exist |
| `TestVerifyAttestationBindsKnownAppIdentity` | Binds attestation to the app's configured package id |
| `TestValidateRequestProofRejectsMissingFields` | Denies proofs with empty hash/nonce/signature |
| `TestValidateRequestProofMalformedTokenIDFailsClosed` | Rejects malformed UUIDs without DB round-trip |
| `TestNonceSingleUse` | A nonce can only be consumed once |

### End-to-end integration tests

```bash
cd tests && go test ./...
```

Verified output (uses testcontainers — Postgres 16 + Redis 7):

```
ok      github.com/kennguy3n/kseal/tests        312.170s
```

If no container runtime is available, these tests skip cleanly.

---

## Understanding the Trust Flow

```
┌─────────┐     ┌──────────┐     ┌───────────────┐     ┌──────────────────┐
│  Device │     │  Server  │     │    Device     │     │     Server       │
│  SDK    │     │  (Trust) │     │     SDK       │     │    (Trust)       │
└────┬────┘     └────┬─────┘     └──────┬────────┘     └────┬─────────────┘
     │  GetNonce   │                  │                     │
     │ ──────────> │                  │                     │
     │  nonce      │                  │                     │
     │ <─────────── │                  │                     │
     │              │                  │                     │
     │  platform attestation (Play Integrity / App Attest)   │
     │  bound to nonce                                         │
     │              │  VerifyAttestation                       │
     │              │ <─────────────────────────────────────────│
     │              │  trust token (JWT) + risk level          │
     │              │ ─────────────────────────────────────────>│
     │              │                  │                     │
     │  setTrustToken                  │                     │
     │              │  ValidateRequestProof (signed HMAC)     │
     │              │ <─────────────────────────────────────────│
     │              │  ALLOW / STEP_UP / DENY                  │
     │              │ ─────────────────────────────────────────>│
```

### The five stages

1. **Initialize** — `KsealSDK.initialize()` configures the SDK with tenant/app
   credentials and a build hash. No network call. Idempotent.

2. **Evaluate risk** — `sdk.evaluateRisk()` runs native RASP probes (debugger
   detection, hook/Frida scanning, root/jailbreak detection, emulator detection)
   and returns a trust level, score, and signal list. Fully offline.

3. **GetNonce** — The device requests a single-use challenge nonce from
   `TrustService/GetNonce`. The nonce is bound to the tenant+app and expires
   after a short TTL.

4. **VerifyAttestation** — The device obtains a platform attestation token
   (Play Integrity on Android, App Attest on iOS) bound to the nonce, then
   submits it to `TrustService/VerifyAttestation`. The server:
   - Consumes the nonce (single-use, anti-replay)
   - Verifies the platform attestation cryptographically
   - Fuses device-reported risk with attestation-derived risk
   - Scores the fused risk against the active policy
   - Mints a short-lived JWT trust token bound to the instance

5. **ValidateRequestProof** — For each protected API call, the SDK produces a
   per-request proof: an HMAC-SHA256 over the trust token id, request hash,
   nonce, and a strictly-increasing sequence number. The server validates the
   proof and returns a decision: **ALLOW**, **STEP_UP** (e.g. require MFA), or
   **DENY**.

### Key security properties

- **Server-authoritative** — the SDK never makes the trust decision. It gathers
  signals and produces proofs; the server decides.
- **Fail-closed** — without a valid platform attestation, the server rejects the
  session. No token is minted.
- **Anti-replay** — nonces are single-use; request proof sequence numbers must
  strictly increase. A replayed proof gets `DENY`.
- **No PII** — the SDK uses a stable, non-PII install identity. Telemetry
  carries only minimized, non-identifying fields.

---

## kseal Capabilities Demonstrated

### On-device RASP (Runtime Application Self-Protection)

Both SDKs run native probes through the shared Rust trust core. The sample apps
call `evaluateRisk()` which triggers all enabled probes and returns a packed
signal bitset, decoded signals, score, confidence, and trust level:

| Probe | Android | iOS |
|-------|---------|-----|
| Debugger detection | `/proc/self/status` TracerPid | `sysctl` `P_TRACED` flag |
| Hook/Frida detection | `/proc/self/maps` + thread name scan | dyld image scan |
| Root/Jailbreak | file-system heuristics | file-system heuristics |
| Emulator detection | build properties + sensor checks | — |
| Screen capture | screen recording API hooks | screen recording API hooks |
| Overlay abuse | accessibility overlay detection | — (no-op on iOS) |
| Accessibility abuse | accessibility service abuse | — (no-op on iOS) |
| Malicious IME | input method editor detection | — (no-op on iOS) |
| Remote access | remote control app detection | — (no-op on iOS) |
| Network risk | VPN/proxy detection | VPN/proxy detection |
| Self-integrity | APK signature + class checksum | code signature + bundle checksum |

### Trust decision evaluation

`sdk.evaluateTrustDecision()` re-runs probes and computes the same
ALLOW / STEP_UP / DENY mapping the server applies, using the active policy's
thresholds. The SDK never enforces this — it surfaces it through the
`onTrustDecision` hook for the host to act on.

### Telemetry

`sdk.reportEvent()` records a telemetry event (e.g. `RUNTIME_TAMPER`,
`DEBUGGER`, `NETWORK_MITM`) with the current risk bitset and coarse metadata.
Events are buffered and batch-compressed (zstd) once `maxBatchEvents` is
reached. `sdk.flushTelemetry()` forces a flush. `sdk.reportPinningFailure()`
emits a `NETWORK_MITM` event with the pinning-failure + MITM signal bits.

### Kill switch

`sdk.isKilled` reads the local kill-switch state (fail-safe: `false` unless an
Ed25519-valid `DISABLE` command has been applied). `sdk.applyKillSwitch()`
verifies and applies a serialized `SignedKillSwitch`. The `onKillSwitchChanged`
hook fires on state transitions so the host can degrade gracefully.

### Config refresh

`sdk.refreshConfig()` re-fetches and verifies a signed config envelope
(Ed25519-signed). The default provider returns `nil` (no network at launch);
a production app wires this to `ConfigService/GetConfig`.

### Continuous protection (re-attestation)

`sdk.startContinuousProtection()` starts a periodic heartbeat that re-runs
probes, recomputes the trust decision, refreshes config, and — at `MEDIUM_RISK`
or above — pulls the latest kill switch. Requires a policy with
`reattest_interval_secs > 0`. `sdk.onAppForeground()` runs one cycle immediately.

### Build-time hardening

kseal includes Gradle (Android) and Xcode (iOS) build plugins that:

- Generate a per-build polymorphism seed (fresh entropy per build)
- Strip debug metadata from compiled classes
- Obfuscate string constants (opt-in)
- Verify native library exploit mitigations (RELRO, NX, PIE, stack canary, etc.)
- Emit a build-proof manifest (build hash, seed digest, tool versions)
- Register the proof with the kseal control plane

See:
- `plugins/gradle/` — Android Gradle hardening plugin
- `plugins/xcode/` — iOS Xcode/SwiftPM hardening plugin

### Server-side trust

The Go server implements `TrustService` with three RPCs:

| RPC | Purpose |
|-----|---------|
| `GetNonce` | Issue a single-use challenge nonce |
| `VerifyAttestation` | Verify platform attestation, fuse risk, mint trust token |
| `ValidateRequestProof` | Validate per-request proof, return ALLOW/STEP_UP/DENY |

All RPCs are reachable via Connect (HTTP/JSON or binary proto):

```bash
curl -fsS localhost:8080/kseal.v1.TrustService/GetNonce \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"<uuid>","app_id":"<uuid>","platform":"PLATFORM_ANDROID"}'
```

### Backend quickstart (full trust flow)

The backend quickstart (`examples/backend-quickstart`) runs the complete
attestation → token → proof chain locally with a mocked JWKS source. It
demonstrates:
- **Clean device → ALLOW** — a legitimate attestation gets a trust token
- **Replayed proof → DENY** — anti-replay via monotonic sequence numbers
- **Tampered device → DENY** — server-authoritative risk scoring denies a
  device with elevated risk signals
- **QueryService reads** — tenant overview + trust-session stats

---

## Troubleshooting

### `protoc` not found

```bash
brew install protobuf
```

The Rust core's `prost-build` requires `protoc` at build time.

### `kseal.h` file not found (iOS build)

The C header is generated by the Rust build and must be staged:

```bash
bash sdk/ios/scripts/build-rust-host.sh
```

### `libkseal_ffi.so` missing (Android build)

Cross-compile the Rust core for Android ABIs first:

```bash
bash sdk/android/scripts/build-rust-android.sh
```

Requires `cargo-ndk`, Android NDK, and Rust Android targets. See
[Prerequisites](#prerequisites).

### `cargo-ndk` fails with "could not find Cargo.toml"

This is a known issue if running `cargo ndk` from the repo root. The
`build-rust-android.sh` script handles this by running from the Rust workspace
directory. If invoking `cargo ndk` manually, run it from `sdk/rust-core/`:

```bash
cd sdk/rust-core
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o ../android/src/main/jniLibs \
  build --release -p kseal-ffi
```

### `libc::kinfo_proc` not found (Rust build on macOS)

The `libc` crate does not export `kinfo_proc` or `P_TRACED` on Darwin. This has
been fixed with local FFI bindings in `sdk/rust-core/kseal-ffi/src/native_probes.rs`.
If you encounter this on an older checkout, pull the latest `main`.

### Gradle: no Java runtime

```bash
brew install --cask temurin@17
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
```

### Gradle: Android SDK not found

```bash
brew install --cask android-commandlinetools
export ANDROID_HOME="/opt/homebrew/share/android-commandlinetools"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
yes | sdkmanager --sdk_root="$ANDROID_HOME" \
  "platforms;android-34" "build-tools;34.0.0" "platform-tools" "ndk;26.1.10909125"
```

### `VerifyAttestation` returns "jws verification failed: token malformed"

This means the `platform_attestation_token` is not a valid JWS (JWT). The dev
attestation provider returns a placeholder string, not a real Play Integrity
verdict. This is expected behavior — the server is fail-closed. To get a real
verdict:

- **Android:** Set `ksealGcpProject` to your Google Cloud project number and use
  a Play-distributed build.
- **iOS:** Implement `AttestationTokenProvider` with `DCAppAttestService` on a
  real device.
- **Full local flow:** Use the [backend quickstart](#step-4--run-the-backend-quickstart-full-trust-flow),
  which swaps the JWKS source for a local key.

### Server not reachable

```bash
make docker-up        # starts server + Postgres + Redis + dashboard
curl -fsS localhost:8080/healthz
```

The Android emulator uses `10.0.2.2` as the host loopback (not `localhost`).

### `make docker-up` fails on console healthcheck

The `kseal-console` (dashboard) container may fail its healthcheck while the
server, Postgres, and Redis come up healthy. The server is still functional:

```bash
curl -fsS localhost:8080/healthz   # should return "ok"
curl -fsS localhost:8080/readyz    # should return "ready"
```

If the console failure blocks `make docker-up`, start the core services only:

```bash
docker compose up -d postgres redis kseal-server
```
