# kseal — Signed Kill Switch (Remote Disable)

The signed kill switch lets an operator **remotely disable or re-enable** a
tenant/app/build through the existing signed-config channel. It is fail-safe:
only an Ed25519 signature that verifies under the tenant's active signing key
flips device state — a forged, altered, or absent command is a no-op.

Parity: Appdome/Promon expose remote disable; kseal makes the command itself
cryptographically verifiable end-to-end and anti-rollback versioned.

## Model

`SignedKillSwitch` is signed over a domain-separated, length-prefixed preimage:

```
sig = Ed25519_sign( tenant_signing_key,
                    "kseal/v1/kill-switch"
                    || tenant_id || app_id || build_hash
                    || command || version || issued_at || reason )
```

- **Scope**: `(tenant_id, app_id?, build_hash?)`. Empty `app_id` is tenant-wide;
  empty `build_hash` covers all builds. The **most specific** matching switch
  wins, so an app/build `ENABLE` can override a tenant-wide `DISABLE`.
- **Anti-rollback**: `version` increases monotonically per scope; re-issuing the
  same scope bumps it. The server folds `(command, version)` into the config
  `ETag` (see [Delivery](#delivery)), and the on-device core rejects a verified
  command whose version is below the highest already accepted for its scope — a
  replayed older command is a no-op. Equal versions are idempotent re-applies.
  Scopes are tracked independently and in-memory for the process lifetime; a
  cold start re-fetches config, where the `ETag` already excludes a superseded
  command.
- **Same trust anchor as config**: kill switches are signed with the per-tenant
  key that signs policy config, so the SDK verifies both with one anchor.
- **Default**: with no applicable switch, the effective command is `ENABLE`
  (availability-preserving). A disable requires an explicit, valid, signed
  command.

## Delivery

`ConfigService.GetConfig` attaches the effective `SignedKillSwitch` to
`ConfigResponse.kill_switch` when the `kill_switch` flag is enabled for the
tenant. The SDK sends `ConfigRequest.build_hash` (the registered hash of the
running binary), so the **most specific** switch — including a build-scoped one
— is resolved and delivered; an empty `build_hash` falls back to app/tenant
scope. The kill-switch identity (`command`, `version`) is folded into the config
`ETag`, so issuing or changing a switch busts cached config within the TTL
instead of waiting for expiry. Because a delivered switch makes the response
scope-specific, such responses are marked `Cache-Control: private`. Lookup is
fail-safe: any error yields no kill switch rather than failing the config fetch.

## Fail-safe verification

`VerifyKillSwitch(pub, ks)` returns `false` (never panics) for a malformed key,
wrong signature length, or altered field. State only flips when it returns
`true`. Every issue is recorded in the audit trail (`killswitch.issue`).

The same verification runs **on device** in the shared Rust core
(`apply_kill_switch`), so the SDK never trusts an unsigned or forged command:

- decode failure → no-op (state unchanged),
- signature invalid under the config anchor → no-op (a forged command can't flip
  state in *either* direction),
- valid command with a stale `version` (below the highest already accepted for
  its `(tenant_id, app_id, build_hash)` scope) → no-op (anti-rollback: a replayed
  older command can't flip state),
- valid `DISABLE` → `is_killed = true`,
- valid `ENABLE`/`UNSPECIFIED` → `is_killed = false` (a server re-enable lifts a
  prior kill).

This mirrors the server's default-`ENABLE` resolution byte-for-byte (a Go↔Rust
golden preimage test pins the layout).

## SDK surfacing (`isKilled`)

The SDK exposes the kill switch as **first-class state**; it never disables the
app on its own — it only surfaces the verified state so the host can degrade
(e.g. read-only mode). The active-response safety rule holds: the SDK does not
kill/lock/wipe by itself.

| Surface | Android | iOS / macOS |
|---|---|---|
| Apply a serialized `SignedKillSwitch` (host-fetched from its own `GetConfig`) | `applyKillSwitch(bytes): Boolean` | `applyKillSwitch(_:) -> Bool` |
| Pull + apply via the `ConfigProvider` (on demand — never at launch) | `refreshKillSwitch(): Boolean` | `refreshKillSwitch() -> Bool` |
| Current verified state | `val isKilled: Boolean` | `var isKilled: Bool` |
| Forced-degrade hook on transition (default no-op) | `var onKillSwitchChanged: ((Boolean) -> Unit)?` | `var onKillSwitchChanged: ((Bool) -> Void)?` |

`ConfigProvider` gains a default-implemented `fetchKillSwitch()` returning
`null`/`nil`, so existing providers keep compiling and stay kill-switch-free
until they opt in. During continuous monitoring (see
[continuous-protection.md](continuous-protection.md)), the SDK pulls the latest
switch as risk escalates.

## RPCs (`ComplianceService`)

| RPC | Request → Response | Notes |
|---|---|---|
| `IssueKillSwitch` | `IssueKillSwitchRequest{tenant_id, app_id, build_hash, command, reason}` → `IssueKillSwitchResponse{kill_switch}` | Signs, persists, audits atomically; bumps version |
| `GetKillSwitchState` | `GetKillSwitchStateRequest{tenant_id, app_id, build_hash}` → `GetKillSwitchStateResponse{effective_command, active}` | Resolves the most-specific switch; client-verifiable |
| `ListKillSwitches` | `ListKillSwitchesRequest{tenant_id}` → `ListKillSwitchesResponse{kill_switches[]}` | All configured switches for the tenant |

## Flag-gating

Delivery is gated by the `kill_switch` feature flag
(`KSEAL_FEATURE_FLAGS`), default off. With the flag off, `GetConfig` never
delivers a kill switch and default behavior on `main` is unchanged.
