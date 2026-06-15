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

## Self-describing storage layout (`risk_bits_layout`)

A stored `risk_bits` value is meaningless without knowing which layout it is in.
Rather than rely on deploy timing to disambiguate, every stored event now carries
its layout explicitly via `StoredEvent.RiskBitsLayout` (`server/shared/risk`):

| `Layout` | value | meaning |
|---|---|---|
| `LayoutUnknown` | 0 | layout not recorded (pre-marker row / older codec) |
| `LayoutWire`    | 1 | raw device/wire bits, **not** yet translated |
| `LayoutServer`  | 2 | already translated to the server layout |

`IngestService` applies `risk.FromWire` before storing and tags the row
`LayoutServer`, so every event written after this change is unambiguous. Readers
never assume a layout — they call `risk.NormalizeStored(bits, layout)`, which:

- `LayoutWire` → applies `FromWire` (translate to server layout),
- `LayoutServer` → returns the bits unchanged,
- `LayoutUnknown` → treats the bits as server layout (the safe default that
  matches behaviour before the column existed; pre-marker rows were already
  stored post-`FromWire`).

This makes double-translation **structurally impossible**: a row is translated
exactly when its marker says it still needs to be, so the simulator, the query
read model, and any future backfill can run repeatedly without corrupting data.
The simulator (`simulator/service.go`) and query projection (`query/service.go`)
both normalize via `NormalizeStored` before scoring or surfacing bits.

### Persistence and codec compatibility

- **ClickHouse** — the `events` table gains `risk_bits_layout UInt8 DEFAULT 0`
  (added idempotently via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`). Existing
  rows materialize `0` = `LayoutUnknown`, i.e. read as server layout — exactly
  the pre-column behaviour, so the column is additive and safe to deploy live.
- **Broker codec** — the internal `StoredEvent` encoding is bumped to **v2**,
  which appends the layout byte after `risk_bits`. The decoder still accepts
  **v1** records (in flight during a rolling upgrade); a v1 record decodes with
  `RiskBitsLayout == LayoutUnknown`. Any version newer than this build is
  rejected so a forward record is never silently misread.
  - **Rollout ordering (Kafka/Redpanda):** the v2 *decoder* is fully
    backward-compatible (reads v1), but a still-running **v1 decoder cannot read
    a v2 record** — it treats it as a poison record, commits past it, and drops
    it (`broker_kafka.go` decode-error path). So the broker tier must be upgraded
    **consumers-before-producers**, or as a single consumer group that rolls
    atomically (old pod stops, new pod resumes from the committed offset). A
    deployment that runs old + new consumers concurrently on the same group can
    lose the v2 records the old pods happen to fetch. This only affects the
    short broker hop; ingest produces and consumes the same internal format, so
    a standard rolling deploy of the ingest fleet is safe.

The live trust decision is unaffected — it always translates the incoming device
bitset per request and never reads stored bits.

### Consumers of stored `risk_bits` (webhooks / SIEM)

External consumers should key on **signal names, not numeric bit positions**.
Bit numbers are an internal detail that can be renumbered; the names are the
stable external contract. Both egress paths therefore emit a named view
alongside the raw integer:

- **Webhook** payloads carry `risk_signals` (a JSON array of names such as
  `["debugger","app_tamper"]`) next to the existing `risk_bits` integer.
- **SIEM** exports add the `risk_signals` field to the minimized privacy
  contract (`server/data-plane/siem/allowlist.go`); the Splunk / Sentinel /
  Elastic onboarding templates map it (multivalue / `dynamic` / `keyword`).

Both paths first call `risk.NormalizeStored`, so the integer **and** the names
are always server layout regardless of how the row was stored. `risk_bits` is
retained unchanged for backward compatibility, but because ingest now stores
server-layout bits, its meaning is server layout going forward (where before this
contract it leaked raw wire bits). Any rule written against the old wire
positions (e.g. treating bit 4 as `DEBUGGER`) must move to the server layout
(bit 4 = `APP_TAMPER`; see the mapping table) — or, preferably, switch to
`risk_signals` and stop depending on positions entirely. Call this out in the
release notes for operators with custom `risk_bits` parsing.

## Pinned on both ends

Any silent renumber must break CI deliberately:

- **Go** — `server/shared/risk/wire_contract_test.go` pins the server layout, the
  full wire→server mapping, the drop-unknown-bits behaviour, and the
  `BitFleetAnomaly`-clear-of-wire-range invariant (`TestWireToServerContract`,
  `TestServerBitLayoutContract`, `TestFleetAnomalyBitClearOfWireRange`).
- **Rust** — `risk::tests::bit_positions_are_stable` pins all 16 wire bit
  positions and `MAX_SIGNAL_BIT`.
- **Egress names + layout** — `server/shared/risk/contract_test.go` pins the
  stable `risk_signals` names (`TestSignalNamesContract`), proves every weighted
  bit has a name (`TestSignalNamesCoversEveryWeightedBit`), and pins the
  `NormalizeStored` layout handling (`TestNormalizeStoredLayouts`).

When changing the layout, update both ends and this table together. Renaming a
`risk_signals` value is a breaking change for external consumers even if no bit
moves — treat the names as the external contract.
