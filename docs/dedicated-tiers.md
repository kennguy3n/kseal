# kseal — Dedicated / Regulated Isolation Tier

By default kseal isolates ~5000 SME tenants logically: one schema, `tenant_id`
on every row, row-level security, and a single platform KEK. The **dedicated /
regulated isolation tier** gives a tenant a **cryptographically separated key
domain** on top of that logical isolation, for customers with stricter
regulatory posture. It is tenant-configurable and off by default — the shared
path and all existing sealed material are unchanged.

Parity: the regulated/dedicated tier Promon and Zimperium ship; kseal makes it
real per-tenant key separation rather than a deployment label.

## Key derivation

A dedicated tenant's secret material is sealed under a **per-tenant key derived
with HKDF-SHA256** from the platform KEK, with the tenant id as salt and a
dedicated domain-separation label:

```
dek_tenant = HKDF-SHA256( ikm = platform_KEK,
                          salt = tenant_id,
                          info = "kseal/v1/dedicated-dek" )
```

- A single derived key never opens another tenant's material; the platform KEK
  is never used directly for dedicated tenants.
- The label is distinct from every other key-derivation use in the system, so a
  dedicated key cannot be confused with any other domain.
- Derived keys are cached per tenant; derivation is constant-time and adds no
  hot-path DB round-trip.

## Self-describing envelope & fail-closed

Dedicated material is wrapped in a self-describing envelope
(`magic 'KSD1'` + version) so `OpenForTenant` detects a **tier change** and
fails closed with a diagnostic error instead of an opaque AES-GCM failure:

- Tenant downgraded but still has dedicated material → `ErrDedicatedDisabled`.
- Tenant upgraded but material predates the tier → `ErrNotDedicatedEnvelope`.
- A resolver lookup error fails closed (no seal/open) rather than silently
  reaching for the platform KEK.

Non-dedicated tenants delegate to the fallback sealer (platform KEK or CMK) with
**byte-identical** output, so the manager is transparent on the default path.

## Relationship to CMK / BYOK

Dedicated isolation and customer-managed keys (see [byok.md](./byok.md)) are
**mutually exclusive per tenant**: the resolver reports a tenant dedicated only
when it has no `cmk_kms_uri`. A CMK tenant keeps its customer-controlled DEK
domain; a dedicated tenant gets the platform-derived per-tenant domain.

## Configuration

- Tenant flag: `tenants.dedicated_isolation` (migration `016`), default
  `false`, admin-scoped, tenant-configurable via `DedicatedResolver`
  (`SetTenantDedicatedIsolation`), cached with the same TTL as the CMK resolver.
- Server flag: `KSEAL_DEDICATED_ISOLATION` (default off) enables the
  `DedicatedKeyManager` wrapper around the base sealer. With it off, every
  tenant uses shared logical isolation under the platform KEK.

## Rotation note

Switching a tenant's tier changes its key domain. Material sealed under the old
domain must be re-sealed (rotate the tenant's signing key) so it is readable
under the new domain; until then `OpenForTenant` fails closed by design.
