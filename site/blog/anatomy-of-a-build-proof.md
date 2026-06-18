# Anatomy of a build proof

When Meridian Pay ships `pay-android`, the kseal Gradle plugin produces one
small artifact that the rest of the platform pivots on: `kseal.build-proof`. It
is a tamper-evident manifest of *exactly* what was hardened, bound together into
a single reproducible `build_hash`. This post opens it up — what's inside, why
two clean builds produce the same hash, and how per-build polymorphism makes a
bypass crafted for one release decay against the next.

The build proof matters because of the server-side trust model: at runtime the
device proves it is running a registered build, and the server checks that claim
against the proof it was given at release time. No proof, no recognition. (See
[Why the trust decision lives on the server](trust-on-the-server.md) for why
that split is the whole game.)

## Hardening happens inside your CI

The first design choice is where hardening runs: **inside your own build**, not
in a cloud service. Your source never leaves CI, there is no per-build cloud
compute, and the plugin auto-wires identity and post-build artifacts. Concretely
the plugin:

- **encrypts** the strings/resources you flag so secrets and lookup keys don't
  sit in plaintext for `strings | grep`;
- optionally **obfuscates** bytecode control flow (`off · low · medium · high`,
  validated — a typo fails the build rather than silently downgrading);
- **strips** debug metadata; and
- **verifies** the native exploit-mitigation posture of every shared library —
  RELRO, NX, PIE, stack canary, FORTIFY, and CFI/MTE/BTI/PAC — recording the
  result rather than trusting it blindly.

All of that lands inside the SDK footprint budgets: the Android AAR stays under
**500 KB** and the iOS slice under **800 KB** (see the
[benchmarks](https://github.com/kennguy3n/kseal/blob/main/docs/reference/benchmarks.md)).

## What's inside the proof

The proof is a manifest, not the artifacts themselves. It records:

- **app + SDK identity** — package id, version, SDK version;
- **the seed digest** — the per-build polymorphism seed, as a hash;
- **tool versions** — so a proof is reproducible against a known toolchain;
- **applied transforms** — which hardening passes ran, at what strength;
- **a sorted list of artifact hashes** — the SHA-256 of each hardened output.

Everything is folded into one value, the `build_hash`. For Meridian Pay's
release that value is:

```
build_hash = e3bb7952a304da35ff93f5ddc20aa9220c6cc9be462016ae2985af3e76a70d73
```

In the reference deployment that digest is a plain SHA-256 of a documented input
string (`meridian/pay-android/1.4.0/seed=00000000`) so anyone can regenerate it:

```bash
printf '%s' "meridian/pay-android/1.4.0/seed=00000000" | sha256sum
```

That `build_hash` is what the runtime self-integrity loop checks against, what
platform attestation is reconciled with on the server, and what a
[kill-switch command](https://github.com/kennguy3n/kseal/blob/main/docs/reference/fixtures/control/kill-switch-command.json)
targets if a specific build turns out to be compromised.

## Reproducible by default

With the default (non-randomized) seed, **two clean builds of identical inputs
produce byte-for-byte identical hardened artifacts and the same `build_hash`.**
That is what makes the proof auditable: a security reviewer can rebuild from
source and confirm the released artifact is exactly what the proof claims. For
auditable CI you pin the seed explicitly:

=== "Android (Gradle)"

    ```kotlin
    ksealHarden { polymorphism { explicitSeedHex.set("<64 hex chars>") } }
    // openssl rand -hex 32
    ```

=== "iOS (Xcode / SwiftPM)"

    ```bash
    export KSEAL_BUILD_SEED="$(openssl rand -hex 32)"
    ```

## Polymorphism: the same source, a different shape each release

Reproducibility and unpredictability sound contradictory, but they operate on
different axes. *Given a seed*, the build is deterministic. *Across seeds*, the
hardened output is different — control-flow layout, string-encryption keystream
and obfuscation choices are all derived from the seed. So each release Meridian
ships has a different internal shape.

The payoff is that **a bypass crafted against one release doesn't transfer.** An
attacker who painstakingly maps the obfuscated control flow of version 1.4.0
finds 1.4.1 rearranged, and has to start over — while kseal's cost to produce
that variation is a single seed change. This is the same per-build-polymorphism
idea that the runtime RASP posture uses, applied at build time.

## Offline and air-gapped builds

Registration doesn't require network access at build time. Both the Gradle and
Xcode plugins write a durable, uploadable manifest when no endpoint is
configured, so you can harden in an air-gapped job and register the proof from a
separate, network-allowed step. The API key is read at execution time and
**never logged**.

## Where the proof goes next

The build proof is the *release-time* anchor of trust. Its runtime counterpart
is attestation: the device proves it's running this exact registered build, and
the server fuses that with everything else before deciding. Follow that thread
in [Inside the risk engine](inside-the-risk-engine.md), or walk the whole
four-step integration in [Secure your app](../secure-your-app.md).
