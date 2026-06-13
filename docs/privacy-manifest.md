# iOS Privacy Manifest generator

`tools/privacy-manifest` generates a valid Apple **`PrivacyInfo.xcprivacy`** for
the kseal SDK directly from the SDK **data contract**, so an integrator embedding
kseal gets an accurate privacy manifest without hand-authoring one. Output is
deterministic (golden-file tested) and the tool is fully offline.

This closes the **Compliance & Evidence → store-disclosure** gap in
[`docs/feature-parity-matrix.md`](feature-parity-matrix.md): incumbents leave the
Apple privacy manifest to the integrator; kseal ships it as a NoOps artifact.

## What it declares

Apple's privacy manifest has two parts that matter for an SDK:

- **`NSPrivacyCollectedDataTypes`** — the privacy-nutrition data types the SDK
  collects, each with linkage, tracking, and *purposes*. The generator emits one
  entry per Apple data type with the deduped union of purposes (so contract items
  that map to the same Apple type are merged deterministically).
- **`NSPrivacyAccessedAPITypes`** — the *required-reason* API declarations with
  their approved reason codes.

It also emits `NSPrivacyTracking` / `NSPrivacyTrackingDomains` (kseal does not
track, so these are `false` / empty by default).

## The data contract is the single source of truth

The generator reads the checked-in contract at
[`tools/privacy-manifest/contract/kseal-data-contract.json`](../tools/privacy-manifest/contract/kseal-data-contract.json),
which is **embedded into the binary** (`go:embed`) so the tool works from any
working directory. Each contract item carries the fields needed to project onto
**both** the Apple and Google disclosure models (see
[`docs/data-safety.md`](data-safety.md)):

```jsonc
{
  "id": "security_risk_signals",
  "proto_fields": ["event_type", "risk_bits", "confidence"],
  "linked_to_identity": false,
  "used_for_tracking": false,
  "optional": false,
  "default_collected": true,
  "ios": {
    "collected_data_type": "NSPrivacyCollectedDataTypeOtherDiagnosticData",
    "purposes": ["NSPrivacyCollectedDataTypePurposeAppFunctionality"]
  },
  "android": { "category": "App info and performance", "data_type": "..." }
}
```

The required-reason API declarations come from the contract's top-level
`ios_required_reason_apis` list (each with `api_category` + approved `reasons`),
so the `NSPrivacyAccessedAPITypes` block is also fully data-driven.

The contract is **pinned to the wire schema**: a test
(`TestContractMatchesTelemetryProto`) fails if a telemetry field is added to
`proto/kseal/v1/telemetry.proto` without a corresponding contract entry, so the
manifest can never silently drift from what the SDK actually transmits.

Items with `default_collected: false` (off by default, e.g. coarse region) are
excluded unless the integrator passes `--include-optional`, because a host app
must declare them only when it enables the corresponding feature.

## Usage

```bash
cd tools/privacy-manifest
go run . > PrivacyInfo.xcprivacy            # plist to stdout
go run . -out ios/PrivacyInfo.xcprivacy     # write the plist to a path
go run . -out-json manifest.summary.json    # machine-readable summary
go run . -include-optional                  # include opt-in data types
go run . -contract path/to/contract.json    # override the embedded contract
```

Via the CLI (same generator, embedded contract):

```bash
kseal compliance privacy-manifest                 # plist to stdout
kseal compliance privacy-manifest --out PrivacyInfo.xcprivacy
kseal compliance privacy-manifest --format json   # JSON summary
```

Drop the generated `PrivacyInfo.xcprivacy` into the kseal SDK bundle (or your app
target if you vendor the SDK). Xcode aggregates it into the app's privacy report.

## Determinism & tests

- **Deterministic output**: types are sorted, purposes deduped and sorted, so the
  same contract always yields byte-identical output.
- **Golden-file tests** assert the rendered plist and JSON summary against
  checked-in goldens (`xcprivacy/testdata`). Regenerate intentionally with
  `go test ./... -update`.
- **Validation**: loading fails closed if the contract is structurally broken —
  e.g. a personal-data item with no store mapping, an iOS mapping missing its
  `collected_data_type`, a required-reason API with no reason codes, or a proto
  field mapped by more than one item — so a malformed contract can never produce
  an invalid manifest.
