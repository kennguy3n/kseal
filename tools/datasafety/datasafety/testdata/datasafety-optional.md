# Google Play Data Safety — kseal

Generated from the kseal SDK data contract. These answers cover the data the
kseal SDK contributes; combine them with your app's own data collection before
submitting the Play Console form.

## Data collection and security

- Does the app collect or share user data? **Yes**
- Is all collected user data encrypted in transit? **Yes**
- Is any data shared with third parties? **No**
- Can users request that their data be deleted? **Yes**
  - Tenant data is namespaced by tenant_id under per-tenant keys; an integrator/tenant can request deletion and offboarding drops those keys (cryptographic erasure). Install identifiers are tenant-scoped salted hashes that rotate, so there is no durable per-user identity to retain.

## Data types collected

| Category | Data type | Collected | Shared | Optional | Purposes |
|---|---|---|---|---|---|
| App info and performance | Other app performance data | Yes | No | No | App functionality; Fraud prevention, security, and compliance |
| Device or other IDs | Device or other IDs | Yes | No | No | App functionality; Fraud prevention, security, and compliance |
| Location | Approximate location | Yes | No | Yes | App functionality; Fraud prevention, security, and compliance |

## Explicitly not collected

- Advertising identifier (IDFA / GAID)
- Behavioral profiling
- Browsing or search history
- Clipboard contents
- Contacts
- Cross-tenant device fingerprint
- Financial account or payment data
- Health or fitness data
- Installed-app inventory
- Keystrokes
- Message or email contents
- Persisted raw IP address (used transiently for edge decisions, never stored raw)
- Photos, videos, or audio
- Precise / GPS location
- Screen contents / screenshots
