# cmd/kseal-cli

CLI tool for build-time protection and tenant management.

`kseal-cli` is the developer entrypoint for the [Build plane](../../ARCHITECTURE.md#build-time-hardening). It runs locally in the tenant's CI/CD (no per-build cloud compute) and exposes commands to:

- Apply build-time hardening / SDK injection to Android and iOS builds (delegating to the [Gradle](../../plugins/gradle) and [Xcode](../../plugins/xcode) plugins).
- Manage tenants, apps, builds, and protection profiles against the [control plane](../../server/control-plane).
- Generate build proofs and MASVS evidence reports.
- Emit CI release-gate verdicts.

New users should start with `kseal init` (guided setup) and `kseal doctor`
(checks auth, app registration, protection policy, and build proof, then tells
you exactly what to do next). Full reference, including output formats,
profiles, completions, and man pages, is in [docs/cli.md](../../docs/cli.md).
