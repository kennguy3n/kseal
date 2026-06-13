# iOS quickstart

A minimal program that integrates the kseal **iOS SDK** end-to-end:

```
initialize → evaluateRisk → GetNonce → attestation → VerifyAttestation
           → setTrustToken → getRequestProof → ValidateRequestProof
```

It depends on the SDK by path (`../../sdk/ios`), so it always tracks the public
surface on `main`, and follows the SDK's documented split: the SDK produces
signals and proofs; the **host owns transport** (`KsealTrustClient`, here
`URLSession`).

It is packaged as a SwiftPM executable so it is reproducible from the command
line on a macOS host (the iOS SDK package also supports macOS for host testing).
**The exact same `KsealSDK` API is what you call from a real iOS app target** —
drop the SDK package into your app, then reuse `KsealTrustClient` and the flow
in `main.swift`.

## Prerequisites

- macOS with the Swift toolchain.
- The Rust trust core the SDK links. From the repo root:

  ```bash
  ./scripts/build-rust-host.sh        # produces libkseal_ffi + kseal.h
  ```

- A running server for the network steps. From the repo root: `make docker-up`.

## Run

```bash
cd examples/ios
swift run kseal-ios-quickstart
```

Configure with environment variables (defaults shown):

| Variable         | Default                  | Meaning                          |
|------------------|--------------------------|----------------------------------|
| `KSEAL_TENANT`   | `acme`                   | Tenant id                        |
| `KSEAL_APP`      | `com.acme.app`           | App id                           |
| `KSEAL_ENDPOINT` | `http://localhost:8080`  | Server base URL (TrustService)   |

Provision a matching tenant/app with the
[backend quickstart](../backend-quickstart) seeder and pass the same ids.

## What's real vs. mocked

- **Real:** SDK init, the native RASP probes, risk scoring in the Rust core,
  nonce binding, the request-proof HMAC, and the three `TrustService` RPCs.
- **Mocked:** only the **external** attestation provider. Apple App Attest /
  DeviceCheck runs only on a real device, so the included
  `DevAttestationTokenProvider` returns a placeholder for host runs. On-device,
  implement `AttestationTokenProvider` with `DCAppAttestService`.

`VerifyAttestation` is **fail-closed**: without a real Apple attestation a stock
server rejects the session, which the program reports. For a fully runnable
chain with the provider mocked at the server's verifier (the documented test
path), see the [backend quickstart](../backend-quickstart).
