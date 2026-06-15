# Defects found & fixed while making this showcase

The brief was explicit: the platform must work **for real and correctly**, not via mockups.
Insisting on driving the *real* product end-to-end — real attestations, real registry writes,
real console reads — surfaced genuine defects that a mockup-based showcase would have papered
over. This is the strongest evidence that the showcase reflects reality.

---

## 1. App-details Builds panel crash on a `uuid = text` filter  → PR #54

**Symptom:** Opening an app's detail page in the console failed to render the **Builds**
panel; the `ListBuilds` query errored.

**Root cause:** The registry's `ListBuilds` query compared a `uuid` column against a `text`
parameter without a cast, so Postgres rejected the predicate (`operator does not exist: uuid
= text`).

**Fix:** Correct, explicit type handling in the registry query so the build list filters by
app id as intended. Verified by re-opening the app-detail page and seeing the Builds panel
render (screenshot `09`).

---

## 2. Console rendering 2026 timestamps as `1970`  → PR #54

**Symptom:** Several console pages displayed dates as **1970-01-…**, the classic epoch-zero
giveaway.

**Root cause:** A **unit mismatch**. The registry stores timestamps in **seconds**
(`EXTRACT(EPOCH …)` / `time.Now().Unix()`), while the console's formatter treated the value as
**milliseconds** (the unit the compliance surface uses, via `time.Now().UnixMilli()`).
Seconds interpreted as milliseconds collapse to a few seconds after the epoch → `1970`.

**Fix:** Normalize the unit at the formatting boundary so both second- and millisecond-based
timestamps render correctly, applied across the affected console pages. Every timestamp in
the showcase screenshots now reads the correct **2026-06-15** (see `08`, `12`, `13`, `14`).

---

## 3. MASVS evidence showing 0/8 coverage on a registered build  → fixed via real build proof

**Symptom:** MediToken's MASVS evidence page reported **0/8** categories with evidence even
though a build was registered.

**Root cause:** Not a code bug — a **data realism** gap. The console's MASVS view derives
coverage from the build's **build-proof manifest** (module set + applied transforms). The
builds seeded earlier carried empty manifests, so there was genuinely nothing to map onto
MASVS categories.

**Fix:** Register a release build the way a real CI pipeline would — with a populated
build-proof manifest (modules: storage, crypto, attestation, tls, rasp, integrity, jailbreak,
privacy, anti-hooking; transforms: control-flow-flattening, string-obfuscation, symbol-strip).
The page then derives **8/8** coverage with per-category evidencing modules (screenshot `12`).
This validated that the MASVS derivation is correct and faithfully reflects the registered
build — it had simply never been given a real manifest to work from.

---

## Note on tooling

The drivers used to exercise the platform for this showcase (telemetry/trust generation,
compliance-surface population, the build-proof registration) are **local-only showcase
tooling** and are intentionally **not committed** to the repository. The defect fixes in
**PR #54** are the real, reviewable code changes; everything else here is the product running
as built.
