# cmd/kseal-cli

CLI tool for build-time protection and tenant management.

`kseal-cli` is the developer entrypoint for the [Build plane](../../ARCHITECTURE.md#build-time-hardening). It runs locally in the tenant's CI/CD (no per-build cloud compute) and exposes commands to:

- Apply build-time hardening / SDK injection to Android and iOS builds (delegating to the [Gradle](../../plugins/gradle) and [Xcode](../../plugins/xcode) plugins).
- Manage tenants, apps, builds, and protection profiles against the [control plane](../../server/control-plane).
- Generate build proofs and MASVS evidence reports.
- Emit CI release-gate verdicts.

**Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 3).
