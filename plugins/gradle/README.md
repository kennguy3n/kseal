# plugins/gradle

Gradle build-time hardening plugin for Android.

Integrates into the tenant's existing Gradle build (after compilation, before packaging) to apply [build-time hardening](../../ARCHITECTURE.md#android):

- R8-compatible obfuscation extension (mapping-file aware so crash symbolication still works)
- DEX / native library hardening, string + resource encryption
- Per-build polymorphism (randomized structure per build)
- Native memory safety (CFI / MTE where supported)
- SDK injection + build proof generation

Runs **locally in CI** — no per-build cloud compute. Invoked directly or via [`kseal-cli`](../../cmd/kseal-cli).

**Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 3).
