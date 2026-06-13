# Desktop (macOS) quickstart

A minimal SwiftPM executable that integrates the kseal **macOS desktop SDK**
end-to-end:

```
initialize → evaluateRisk (offline) → establishTrustSession → authorizeRequest
```

It depends on the SDK by path (`../../sdk/desktop/macos`), so it always tracks
the public surface on `main`, and follows the documented integration in
[`docs/desktop-sdk.md`](../../docs/desktop-sdk.md).

## Prerequisites

- macOS with the Swift toolchain (Xcode or Command Line Tools).
- The shared Rust trust core, which the SDK links. Build it once from the repo
  root:

  ```bash
  ./scripts/build-rust-host.sh        # produces libkseal_ffi.{dylib,so} + kseal.h
  ```

- A running server for the network steps (steps 3–4). From the repo root:

  ```bash
  make docker-up
  ```

## Run

```bash
cd examples/desktop-macos
swift run kseal-desktop-quickstart
```

Configure the target with environment variables (defaults shown):

| Variable         | Default                  | Meaning                          |
|------------------|--------------------------|----------------------------------|
| `KSEAL_TENANT`   | `acme`                   | Tenant id                        |
| `KSEAL_APP`      | `com.acme.app`           | App id                           |
| `KSEAL_ENDPOINT` | `http://localhost:8080`  | Server base URL (TrustService)   |

To make `establishTrustSession` succeed against a real server you need a tenant
+ app registered with a build hash the server recognizes, and a code-signed +
notarized build whose attestation the server's macOS verifier accepts. Use the
[backend quickstart](../backend-quickstart) seeder to provision the
tenant/app, and pass the same ids here.

## What's real vs. mocked

- **Real:** the native macOS integrity probes (code signature, notarization,
  hardened runtime, dylib-injection, optional debugger), the Rust trust core
  scoring over the C ABI, nonce binding, the request-proof HMAC, and the three
  `TrustService` RPCs.
- **Mocked:** only the **external** platform notary. `LocalCodeIntegrityAttestor`
  (the SDK default) builds the attestation token from the process's real
  code-signing info; there is no third-party Apple service call in the loop.

On an unsigned dev build the server may reject the attestation — that's correct,
fail-closed behavior. The sample prints the server's verdict and continues, so
you can see each stage of the flow.

## Offline-only mode

Steps 1–2 (`initialize` + `evaluateRisk`) perform **no network I/O** and run
without a server. If you only want to see local integrity scoring, run the
sample without `make docker-up`; it will report the risk assessment, note that
the server is unreachable, and exit cleanly.
