# Google Play Data-Safety helper

`tools/datasafety` generates the **Google Play Console Data-Safety** answers for
the kseal SDK from the same SDK **data contract** that drives the iOS privacy
manifest (see [`docs/privacy-manifest.md`](privacy-manifest.md)). It emits both a
machine-readable form (JSON) and a human-readable Markdown summary an integrator
can paste alongside their own answers. Output is deterministic and offline.

This closes the **Compliance & Evidence → store-disclosure** gap in
[`docs/feature-parity-matrix.md`](feature-parity-matrix.md): the Play Data-Safety
form falls out of the data contract as a NoOps artifact instead of being
hand-authored per release.

## What it answers

The Play Console Data-Safety form has section-level answers and a per-data-type
table; the helper fills both from the contract:

- **Section answers** — does the app collect/share user data, is all collected
  data **encrypted in transit**, and can users **request deletion**. These come
  from the contract's `transport`, `data_sharing`, and `store_disclosure`
  blocks, so no policy answer is hardcoded.
- **Per-type rows** — one row per Android-mapped personal-data item, with the
  Play **category**, **data type**, **purposes**, whether it is **shared** with
  third parties, **processed ephemerally**, and **optional** (whether the user
  can use the app without providing it).

The contract's `not_collected` list is surfaced verbatim so the integrator can
affirmatively answer "not collected" for those categories.

## The data contract is the single source of truth

Each contract item carries an `android` projection onto the Play model:

```jsonc
{
  "id": "security_risk_signals",
  "personal_data": true,
  "optional": false,
  "android": {
    "category": "App info and performance",
    "data_type": "Other app performance data",
    "purposes": ["Fraud prevention, security, and compliance",
                 "App functionality"]
  }
}
```

Only items flagged `personal_data` with an `android` mapping become form rows
(build/policy hashes and envelope timestamps are excluded because they identify
the artifact, not the user). Rows are sorted by `(category, data_type)` for
deterministic output. Items with `default_collected: false` are included only
with `--include-optional`.

## Usage

```bash
cd tools/datasafety
go run .                                  # Markdown summary to stdout
go run . -out-md data-safety.md           # write the Markdown summary
go run . -out-json data-safety.json       # machine-readable form
go run . -include-optional                # include opt-in data types
go run . -contract path/to/contract.json  # override the embedded contract
```

Via the CLI (same generator, embedded contract):

```bash
kseal compliance data-safety                  # Markdown summary to stdout
kseal compliance data-safety --format json    # machine-readable form
kseal compliance data-safety --out data-safety.md
```

The Markdown summary maps directly onto the Play Console questions:

```
# Google Play Data Safety — kseal
## Data collection and security      (collect? share? encrypted-in-transit? deletion?)
## Data types collected              (category / type / purposes / shared / optional)
## Explicitly not collected
```

## Determinism & tests

- **Deterministic output**: rows sorted, purposes deduped and sorted, so the same
  contract always yields byte-identical JSON and Markdown.
- **Golden-file tests** assert the rendered JSON and Markdown against checked-in
  goldens (`datasafety/testdata`); regenerate intentionally with
  `go test ./... -update`.
- **Same contract as iOS**: because both store generators read the one contract,
  the Apple and Google disclosures cannot disagree about what kseal collects.
