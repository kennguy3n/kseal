# Get secure fast — Windows (.NET)

Add server-decided app trust to a Windows .NET app in ~5 minutes. The SDK
verifies the running app's Authenticode signature, gathers integrity signals,
and produces per-request proofs bound to a hardware-backed key; the **server**
makes the trust decision (ALLOW / STEP_UP / DENY).

## Requirements

- **.NET 8.0** or newer, Windows 10 1809+ (the package targets `net8.0` so it
  also builds cross-platform for host testing).
- The native `kseal_ffi` library on the load path. For local/host testing point
  `KSEAL_FFI_LIBRARY` at the built `libkseal_ffi.{so,dylib,dll}`
  (see [`scripts/build-rust-host.sh`](scripts/build-rust-host.sh)).
- A tenant + app provisioned on your kseal control plane (`tenantId`, `appId`).
  Seed a local dev tenant with
  [`examples/backend-quickstart`](../../../examples/backend-quickstart).

## 1. Reference the package

```xml
<PackageReference Include="Kseal.Desktop" Version="<version>" />
```

See [CHANGELOG.md](CHANGELOG.md) for versions.

## 2. Initialize once (no network at launch)

```csharp
using Kseal.Desktop;

using var sdk = KsealDesktopClient.Initialize(
    tenantId: "<tenant>",
    appId: "<app>",
    options: new KsealDesktopOptions { BuildHash = "sha256:<your-build-hash>" });
```

`Initialize` is safe to call once at startup; subsequent calls return the same
instance. The proof key is bound to the platform key store (DPAPI/TPM) when
available. No network I/O at launch. `KsealDesktopClient` is `IDisposable`.

## 3. Evaluate local risk (offline, cheap)

```csharp
RiskAssessment risk = sdk.EvaluateRisk();
// risk.TrustLevel / risk.Score / risk.IsClean / risk.Signals
```

## 4. Establish a trust session, then sign requests

Given an `ITrustSessionClient` (your transport), `EstablishTrustSession` runs
the whole `GetNonce → attest → VerifyAttestation → SetTrustToken` handshake and
stores the token:

```csharp
TrustSession session = sdk.EstablishTrustSession(client);
if (!session.Accepted) return;                          // server fail-closed

// Sign a protected request and let the server decide in one call:
RequestProofDecision decision = sdk.AuthorizeRequest(Sha256("POST /v1/orders"), client);
// decision is ALLOW / STEP_UP / DENY
```

Prefer the lower-level `GetRequestProof(byte[])` if you own the validate
round-trip. React to `decision`: proceed on ALLOW, prompt MFA on STEP_UP, block
on DENY.

## 5. Handle errors by type, not message

Every SDK failure is a [`TrustCoreException`](src/Kseal.Desktop/TrustCore.cs)
carrying a typed [`KsealErrorCode`](src/Kseal.Desktop/TrustCore.cs):

```csharp
try
{
    var decision = sdk.AuthorizeRequest(hash, client);
}
catch (TrustCoreException ex)
{
    switch (ex.Code)
    {
        case KsealErrorCode.TrustTokenMissing: sdk.EstablishTrustSession(client); break;
        case KsealErrorCode.ConfigRejected:    ReportAndFallBack(ex); break;
        default:                               Log(ex); break;
    }
}
```

## Next steps

- Supply an `EnterprisePolicy` via `KsealDesktopOptions` for managed fleets.
- Batch telemetry with `ReportEvent(...)` / `FlushTelemetry()`.
