# MASTG verification-procedure runner

`tools/mastg` turns the repo's MASVS control mapping into an executable
**[OWASP MASTG](https://mas.owasp.org/MASTG/)** verification checklist and emits a
per-release **pass / observed / pending** report. It complements
[`tools/masvs-report`](../tools/masvs-report) (which proves *build-time* control
coverage) by adding the **device-test verification layer** on top: which MASTG
procedures were actually run against a release, and whether the release is clear
to ship.

This closes the **Compliance & Evidence → verification evidence** gap in
[`docs/feature-parity-matrix.md`](feature-parity-matrix.md): MASTG verification
becomes a self-service, deterministic, fail-safe report rather than a manual
audit. The runner does **not** edit `tools/masvs-report`; it consumes its output.

## Where the procedures come from

The catalog is parsed from [`docs/masvs-mapping.md`](masvs-mapping.md) — the same
authoritative MASVS mapping the rest of the repo uses. Each control row's
**MASTG verification** cell is parsed into one or more procedures, so adding a
control or a MASTG test to the mapping automatically adds it to the runner with
no code change.

### Plane classification

Each procedure is classified by *how* it is verified, parsed from the
verification-method label (not hardcoded), which determines its fail-safe
default:

| Plane      | Recognized from                     | Default when no evidence |
|------------|-------------------------------------|--------------------------|
| `device`   | one or more `MASTG-*` test tokens   | `pending` (must be run)  |
| `server`   | a `Server …` method label           | `informational`          |
| `other`    | any other named method label        | `informational`          |

Only **device** procedures default to `pending`, because only they require a
device test against the build. Server/other procedures are verified elsewhere and
are surfaced for completeness but never gate.

## Evidence: explicit assertions + masvs-report overlay

The runner is **fail-safe**: with no evidence it reports every device procedure as
`pending` and blocks nothing. You raise confidence with two evidence sources.

**1. Explicit per-release assertions** (`--evidence FILE`):

```jsonc
{
  "release": "2026.6.0",
  "platform": "android",
  "build_hash": "ab12cd…",
  "results": [
    { "match": "MASTG-TEST-0201", "status": "pass", "note": "keystore-backed" },
    { "match": "MASVS-STORAGE",   "status": "pass", "note": "area signed off" },
    { "match": "logs",            "status": "fail", "note": "PII in logcat" }
  ]
}
```

`match` is matched **case-insensitively as a substring** against each procedure's
objective, kseal control, id, or any MASTG test token — so a single assertion can
cover one procedure or a whole test area. When multiple assertions match a
procedure, the **last** one wins, letting a specific row refine a bulk assertion.

**2. masvs-report overlay** (`--masvs-report FILE`): a
[`tools/masvs-report`](../tools/masvs-report) JSON is overlaid as build-proof. A
procedure with build evidence but no explicit device assertion becomes
`observed` (supporting evidence exists, full MASTG device verification not yet
asserted).

### Status precedence

For each procedure, in order: an explicit assertion wins → else a masvs-report
overlay yields `observed` → else the plane's fail-safe default applies
(`device → pending`, `server`/`other → informational`).

| Status          | Meaning                                                    | Gates? |
|-----------------|------------------------------------------------------------|--------|
| `pass`          | explicit device-test assertion verified the check          | no     |
| `fail`          | explicit assertion reported the check failed               | **yes**|
| `observed`      | build-proof exists, full device verification not asserted  | no     |
| `pending`       | device procedure with no evidence yet                      | only with `--require-pass` |
| `informational` | verified outside MASTG device scope (server/other)         | no     |
| `not-applicable`| explicitly marked N/A for this release                     | no     |

## Gating

By default **only `fail` blocks** a release, so absent evidence never blocks by
itself (fail-safe). `--require-pass` is the strict final-sign-off mode: pending
device procedures also block. The process exit code reflects gating so CI can act
on it:

- `0` — not blocked
- `3` — release blocked (`tools/mastg` binary); the CLI maps this to exit `7`
- `1` — usage/IO error

## Usage

```bash
cd tools/mastg
# fail-safe report from the repo mapping, no evidence (everything pending):
go run . -catalog ../../docs/masvs-mapping.md

# with per-release evidence + build proof, strict sign-off, JSON for CI:
go run . -catalog ../../docs/masvs-mapping.md \
         -evidence release-evidence.json \
         -masvs-report ../../masvs-report.json \
         -require-pass -format json -out mastg-report.json
```

Via the CLI (locates `docs/masvs-mapping.md` by walking up from the working dir):

```bash
kseal compliance mastg                         # Markdown report to stdout
kseal compliance mastg --format json           # machine-readable report
kseal compliance mastg --evidence ev.json --require-pass
kseal compliance mastg --masvs-report report.json --out mastg-report.md
```

## Determinism & tests

- **Deterministic output**: procedures keep catalog order, grouped by category;
  the same inputs always yield byte-identical Markdown and JSON.
- **Golden-file tests** cover the base (no-evidence) report and an evidenced
  report in both formats (`mastg/testdata`); regenerate intentionally with
  `go test ./... -update`.
- **Fail-safe by construction**: a test asserts that the default report (no
  evidence) never blocks, and that a single `fail` assertion does block.
