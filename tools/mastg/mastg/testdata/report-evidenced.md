# kseal MASTG verification report

- Release: `2.0`
- Platform: `android`
- Build hash: `abc123`

## Summary

| Status | Count |
|---|---|
| pass | 1 |
| observed | 2 |
| pending | 0 |
| fail | 0 |
| informational | 2 |
| not-applicable | 0 |

**No failing procedures.**

## Procedures

### MASVS-STORAGE

| Objective | Status | Method | Plane | Notes |
|---|---|---|---|---|
| No sensitive data in logs | pass | MASTG-STORAGE | device | logcat clean |
| No secrets in app storage | observed | MASTG-RESILIENCE, MASTG-STORAGE | device | masvs-report build evidence: partial |
| Tenant data isolated at rest | informational | Server test | server | verified by server-side test; outside MASTG device scope |

### MASVS-CRYPTO

| Objective | Status | Method | Plane | Notes |
|---|---|---|---|---|
| Strong, current algorithms | observed | MASTG-CRYPTO | device | algorithm review |
| Deterministic serialization | informational | Property test | other | verified by "Property test"; outside MASTG device scope |
