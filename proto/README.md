# proto

Protobuf definitions for all services and SDK ↔ server communication.

The single source of truth for wire formats across the [device plane](../sdk), [data plane](../server/data-plane), and [control plane](../server/control-plane). Protobuf is chosen for its compact, schema-versioned, deterministic encoding; telemetry batches are framed here and compressed with zstd on the wire (see [ARCHITECTURE.md](../ARCHITECTURE.md#compression)).

Expected schema groups:

- Telemetry events (compact event types, packed risk bits, confidence levels)
- Attestation challenge/response + trust tokens
- Signed request proofs
- Config / policy bundles (signed)
- gRPC / Connect service definitions

Generated Go, Kotlin/Java, Swift, and Rust bindings are produced from these definitions.

**Status:** scaffold — see [PROGRESS.md](../PROGRESS.md) (Phase 1).
