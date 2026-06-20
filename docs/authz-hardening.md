# Authorization hardening

kseal now makes authorization decisions from an explicit per-procedure policy table instead of a binary "API key present" check.

## API key scopes

Tenant API keys must carry the scopes needed by the RPC they call. Empty scope lists no longer imply full access. Supported wildcard behavior is explicit:

- `registry:*`, `policy:*`, `query:*`, `webhook:*`, `siem:*`, and `compliance:*` grant all scopes in that namespace.
- `*` grants all non-platform tenant scopes.
- Platform scopes are never granted to tenant keys by `*`.

## Platform administration

Tenant provisioning and tenant enumeration are platform-admin operations. `CreateTenant` requires `platform:tenant:write`; `ListTenants` requires `platform:tenant:read`. The principal must also be marked as a platform admin, so a tenant API key cannot satisfy platform scopes accidentally.

## Device-plane compatibility

Public pre-attestation calls remain limited to nonce issuance and attestation verification, and both require a known app record. Config and telemetry calls must run under a validated tenant/device credential context; a request body `tenant_id` is treated as a claim, not authority. SDKs that previously called config or telemetry without a credential need to roll out app/trust-token credentials before enabling those flows.
