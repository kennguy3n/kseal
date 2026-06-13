# kseal — Audit Trail & Data-Processing Registry

The compliance backend gives every tenant a **tamper-evident audit trail** of
control-plane mutations and a **machine-readable data-processing registry**.
Both are tenant-scoped, carry no PII, and are exposed read-only to the
compliance console (WS-M) and store-disclosure tooling (WS-L) over
`ComplianceService`.

Parity: incumbents (Appdome, Promon, Zimperium) ship partial audit/compliance
reporting; kseal makes it a first-class, cryptographically verifiable surface.

## Audit trail

Every mutation (policy/key/webhook change, kill-switch issue, canary
set/promote/rollback, data-processing edit) appends an `AuditEvent` to the
tenant's chain. Events are **append-only** and **hash-chained**:

```
hash_n = SHA256( "kseal/v1/audit-event"
                 || tenant_id || seq || action || resource_type || resource_id
                 || actor_key_id || canonical(metadata) || created_at_ms
                 || hash_{n-1} )
```

- `seq` is a per-tenant monotonic counter starting at 1.
- Each event commits to its predecessor's hash, so any insert, edit, drop, or
  reorder breaks the chain and is detected by `VerifyAuditChain`.
- The preimage is length-prefixed and domain-separated, so an audit hash can
  never collide with a kill-switch signature or config envelope.
- Metadata is restricted to coarse, non-PII key/values; raw values are never
  logged.

### Database enforcement

`audit_events` enables **row-level security** (tenant isolation) and a
**BEFORE UPDATE OR DELETE trigger** that rejects any mutation outside the
privileged admin-bypass context (`app.bypass_rls = 'on'`). The chain is
therefore append-only even against a compromised application path; offboarding
cascades still work via the admin context.

## Data-processing registry

`DataProcessingRecord` is a per-app (or tenant-wide) disclosure of data
categories, processing purpose, retention window, legal basis, and third-party
sharing. It backs store-disclosure generation and the compliance console.
Upserts are keyed by `(tenant_id, app_id)` and themselves audited
(`dataprocessing.put`).

## Read/write RPCs (`ComplianceService`)

| RPC | Request → Response | Notes |
|---|---|---|
| `ListAuditEvents` | `ListAuditEventsRequest{tenant_id, action, resource_type, start_time, end_time, page_size, page_token}` → `ListAuditEventsResponse{events[], next_page_token}` | Newest-first, keyset-paginated, tenant-filtered |
| `VerifyAuditChain` | `VerifyAuditChainRequest{tenant_id}` → `VerifyAuditChainResponse{intact, verified_count, broken_seq, head_hash}` | Recomputes the chain; `broken_seq` = first failure |
| `GetDataProcessingRegistry` | `GetDataProcessingRegistryRequest{tenant_id}` → `GetDataProcessingRegistryResponse{records[]}` | All records for the tenant |
| `PutDataProcessingRecord` | `PutDataProcessingRecordRequest{tenant_id, app_id, data_categories[], purpose, retention_days, legal_basis, third_party_sharing}` → `PutDataProcessingRecordResponse{record}` | Upsert by `(tenant, app)`; audited |

Every RPC enforces that the caller's authenticated tenant equals the request
`tenant_id` (cross-tenant → `PermissionDenied`; missing principal →
`Unauthenticated`).

## Flag-gating

The audit trail records unconditionally for control-plane mutations (it is the
source of truth). The `audit_trail` feature flag gates any optional surfacing.
All compliance flags follow the repo `KSEAL_FEATURE_FLAGS` convention
(`tenant:flag=true`, `*:flag=false`), default off.
