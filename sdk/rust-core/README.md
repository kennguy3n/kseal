# sdk/rust-core

Shared **Rust trust core** used by both the [Android](../android) and [iOS](../ios) SDKs.

The Rust core owns everything that must be **identical, deterministic, and audited once** across platforms:

- Policy evaluation and local risk scoring
- Event normalization (native signals → canonical schema)
- Crypto message formats (request proofs, attestation envelopes)
- Compression (protobuf + zstd batching, shared dictionaries)
- Deterministic serialization (byte-stable output for signing/verification)
- FFI-safe shared trust logic (UniFFI / C ABI)

**Platform probes stay native** — the core consumes signals passed in from the platform SDKs; it does not call OS APIs directly.

See [ARCHITECTURE.md](../../ARCHITECTURE.md#rust-core-scope). **Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 1).
