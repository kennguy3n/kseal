# kseal MASTG verification report

- Release: `2.1`

## Summary

| Status | Count |
|---|---|
| pass | 0 |
| observed | 0 |
| pending | 2 |
| fail | 1 |
| informational | 2 |
| not-applicable | 0 |

**Release blocked:** 1 failed procedure(s): MASVS-STORAGE/no-sensitive-data-in-logs

## Procedures

### MASVS-STORAGE

| Objective | Status | Method | Plane | Notes |
|---|---|---|---|---|
| No sensitive data in logs | fail | MASTG-STORAGE | device | PII leaked to logcat |
| No secrets in app storage | pending | MASTG-RESILIENCE, MASTG-STORAGE | device | no evidence supplied; run this MASTG procedure against the release build |
| Tenant data isolated at rest | informational | Server test | server | verified by server-side test; outside MASTG device scope |

### MASVS-CRYPTO

| Objective | Status | Method | Plane | Notes |
|---|---|---|---|---|
| Strong, current algorithms | pending | MASTG-CRYPTO | device | no evidence supplied; run this MASTG procedure against the release build |
| Deterministic serialization | informational | Property test | other | verified by "Property test"; outside MASTG device scope |
