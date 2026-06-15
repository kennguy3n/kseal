# kseal — Risk-bit Contract (wire ↔ server)

Two distinct risk-bit namespaces meet in the trust decision:

- **Wire / device layout** — the Rust core's `RiskBitset`, a `u64` with bits
  `0..15` (`sdk/rust-core/kseal-core/src/risk.rs`). This is what a device reports
  on `AttestationRequest.risk_bitset` and `TelemetryEvent.risk_bits`, and what
  the platform SDKs populate.
- **Server layout** — `server/shared/risk`, bits `0..10` plus the server-only
  `BitFleetAnomaly = 1 << 32`. This is what policy weights, the scorer, the
  simulator, and the SIEM field mapping all assume.

They overlap numerically but **not semantically**: e.g. wire bit 4 is `DEBUGGER`
while server bit 4 is `APP_TAMPER`. OR-fusing a raw device bitset with
server-derived bits therefore mis-scores every signal whose meaning differs by
position — a latent foot-gun where one `u64` is read under two layouts.

## The contract

`risk.FromWire(wire uint64) uint64` is the single source of truth that translates
the device/wire layout into the server layout. It is applied at every
device → server boundary **before** any fusion or scoring:

- `TrustService.VerifyAttestation`: `Fuse(risk.FromWire(m.RiskBitset), res.RiskBits)`.
- `IngestService` telemetry: stored bits and the derived `RiskLevel` use
  `risk.FromWire(ev.RiskBits)`.

So the server never operates on raw device bits, and the fleet engine's signal
masks (server layout) match what is actually scored.

### Mapping

| wire bit | wire signal | → server bit |
|---|---|---|
| 0 | ROOT | `BitRootJailbreak` |
| 1 | JAILBREAK | `BitRootJailbreak` |
| 2 | EMULATOR | `BitEmulator` |
| 3 | SIMULATOR | `BitEmulator` |
| 4 | DEBUGGER | `BitDebugger` |
| 5 | HOOKING | `BitHooking` |
| 6 | TAMPER | `BitAppTamper` |
| 7 | APP_INTEGRITY | `BitAppTamper` |
| 8 | NETWORK_MITM | `BitNetworkMITM` |
| 9 | ENVIRONMENT | `BitEnvironmentRisk` |
| 10 | PROXY | `BitEnvironmentRisk` |
| 11 | USER_CA | `BitNetworkMITM` |
| 12 | PINNING_FAILURE | `BitNetworkMITM` |
| 13 | ATTESTATION_FAIL | `BitAttestationFail` |
| 14 | SECURE_HW_MISSING | `BitDeviceIntegrity` |
| 15 | REPACKAGED | `BitAppTamper` |

Multiple wire bits may fold onto one server bit (e.g. ROOT and JAILBREAK), and
one wire bit maps to exactly one server bit. Wire bits above 15 carry no server
meaning and are dropped (not scored against an unrelated bit). `BitFleetAnomaly`
sits at bit 32, well clear of the wire range, so a device can never forge it and
it never collides with a translated bit.

## Historical telemetry written before this contract

`IngestService` now stores `risk.FromWire(ev.RiskBits)`, so every event written
**after** this change carries server-layout bits and is scored correctly by the
simulator and analytics. Events written **before** it carry the old wire-layout
bits in their `risk_bits` column, so the simulator (which scores stored bits with
server weights) mis-scores those rows for any signal whose meaning differs by
position (bit ≥ ~4).

No destructive backfill is run, by design:

- There is **no per-row layout/version marker**, so a blind re-translation would
  double-apply `FromWire` to already-correct post-fix rows and corrupt them. A
  one-time, timestamp-cutoff backfill (`received_at < deploy_time`) is the only
  safe form and is intentionally left as an opt-in operator action rather than an
  automatic migration, to keep the NoOps default safe.
- The discontinuity is **bounded and self-healing**: raw events age out of each
  tenant's retention window (`server/data-plane/ingest/retention.go`), so once a
  full window has elapsed past the deploy, every remaining row is server-layout.
  Only tenants configured to *retain indefinitely* (`days <= 0`) keep pre-fix
  rows; such a tenant can run the cutoff backfill above if exact historical
  simulation over that range is required.

The live trust decision is unaffected — it always translates the incoming device
bitset per request and never reads stored bits.

### Consumers of stored `risk_bits` (webhooks / SIEM)

The webhook sink and the SIEM exporter emit the stored `risk_bits` integer
verbatim (they do not expand it into per-bit named fields). Because ingest now
stores server-layout bits, those egress fields are **server layout** going
forward, where before this change they carried the raw device/wire layout. This
is the correct behaviour — wire bits should never have leaked to consumers, and
the server-side SIEM field names already describe the server layout — but any
external integration or SIEM correlation rule written against the old wire
positions (e.g. treating bit 4 as `DEBUGGER`) must be updated to the server
layout (bit 4 = `APP_TAMPER`; see the mapping table above). Call this out in the
release notes for operators with custom `risk_bits` parsing.

## Pinned on both ends

Any silent renumber must break CI deliberately:

- **Go** — `server/shared/risk/wire_contract_test.go` pins the server layout, the
  full wire→server mapping, the drop-unknown-bits behaviour, and the
  `BitFleetAnomaly`-clear-of-wire-range invariant (`TestWireToServerContract`,
  `TestServerBitLayoutContract`, `TestFleetAnomalyBitClearOfWireRange`).
- **Rust** — `risk::tests::bit_positions_are_stable` pins all 16 wire bit
  positions and `MAX_SIGNAL_BIT`.

When changing the layout, update both ends and this table together.
