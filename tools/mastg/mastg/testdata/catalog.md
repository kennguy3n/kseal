# Fixture MASVS mapping

Prose before any category is ignored.

## How to Read This Mapping

Ignored non-category section.

## MASVS-STORAGE

Objective: sensitive data is stored securely and not exposed via logs or
backups.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| No sensitive data in logs | Privacy guard strips identifiers at source | Device plane: privacy guard | MASTG-STORAGE: inspect logcat/oslog; assert no PII |
| No secrets in app storage | No static secrets; keys hardware-bound | Secret protection | MASTG-STORAGE + MASTG-RESILIENCE: static scan binary; runtime sandbox dump |
| Tenant data isolated at rest | Logical tenant_id namespacing | Control plane | Server test: attempt cross-tenant_id read; assert deny |

---

## MASVS-CRYPTO

Objective: cryptography uses current algorithms and hardware-backed keys.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| Strong, current algorithms | Modern AEAD + signatures | Rust trust core | MASTG-CRYPTO: review algorithms; assert no MD5/SHA-1/ECB |
| Deterministic serialization | Canonical message formats | Rust core | Property test: round-trip determinism (tenant-neutral) |

---

## Coverage Summary

Ignored trailing table.

| MASVS category | Controls |
|---|---|
| STORAGE | 5 |
