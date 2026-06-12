# plugins/xcode

Xcode build-time hardening plugin for iOS.

Distributed as an **XCFramework + Swift Package + Xcode build plugin** and applies [build-time hardening](../../ARCHITECTURE.md#ios):

- Mach-O integrity (section hashing, load-command validation)
- Swift / ObjC string + symbol hardening, metadata stripping
- Jailbreak / injection detection wired in at build time
- Per-build polymorphism
- App Attest provisioning + build proof generation

Runs **locally in CI** — no per-build cloud compute. Invoked directly or via [`kseal-cli`](../../cmd/kseal-cli).

**Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 3).
