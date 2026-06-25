//! Selection of native vs virtualized execution by obfuscation strength.
//!
//! The canonical `ObfuscationStrength` (OFF/LOW/MEDIUM/HIGH, default OFF) lives
//! in the Gradle hardening plugin
//! (`plugins/gradle/.../internal/ObfuscationStrength.kt`), where it gates the
//! Phase-5.1 bytecode obfuscator. This module mirrors that ladder on the Rust
//! side so the virtualization tier plugs into the **same** knob: virtualization
//! is the most aggressive transform and is therefore gated behind `HIGH`
//! (opt-in), exactly like MBA + control-flow flattening are in the plugin.
//!
//! Crucially the selection is **behaviour-preserving**: [`cohort_bucket`]
//! returns the identical value for every strength — `HIGH` merely routes the
//! computation through the VM instead of native code. That parity is what lets
//! the tier be enabled per-build without risk to outputs, and is pinned by the
//! tests here and in [`super::ir`].

use super::ir::{self, demo_cohort_expr, demo_cohort_native, DEMO_COHORT_INPUTS};
use super::{decode_with_seed, encode_with_seed, interp, BuildSeed, Program};

/// The strength ladder, mirroring the Gradle plugin's `ObfuscationStrength`.
///
/// Defaults to [`ObfuscationStrength::Off`]; virtualization engages only at
/// [`ObfuscationStrength::High`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum ObfuscationStrength {
    /// No transforms (default).
    #[default]
    Off,
    /// String-constant encryption only (plugin semantics; no virtualization).
    Low,
    /// Opaque predicates on a subset (plugin semantics; no virtualization).
    Medium,
    /// Maximum hardening. The only level at which this tier virtualizes a
    /// selected routine.
    High,
}

impl ObfuscationStrength {
    /// Whether the code-virtualization tier should virtualize eligible routines
    /// at this strength. Only `HIGH` opts in.
    #[must_use]
    pub fn virtualizes(self) -> bool {
        self == ObfuscationStrength::High
    }
}

/// A decoded, ready-to-run virtualized form of [`demo_cohort_native`], built
/// once per `seed`.
///
/// A shipped `HIGH` build decodes the polymorphic bytecode once at startup (not
/// per call); this type models that: construct it once, then call
/// [`VirtualCohort::run`] on the hot path.
#[derive(Debug, Clone)]
pub struct VirtualCohort {
    program: Program,
}

impl VirtualCohort {
    /// Lowers the demo cohort expression, encodes it under `seed`, and decodes
    /// it back to a runnable [`Program`].
    ///
    /// # Panics
    /// Never for the fixed demo expression: it is statically known to fit the
    /// register bank and to round-trip under any seed (asserted by tests).
    #[must_use]
    pub fn build(seed: &BuildSeed) -> Self {
        let lowered = ir::lower("demo_cohort", DEMO_COHORT_INPUTS, &demo_cohort_expr())
            .expect("demo cohort expression lowers");
        let bytes = encode_with_seed(&lowered.program, seed);
        let program = decode_with_seed(&bytes, seed).expect("demo cohort decodes under its seed");
        Self { program }
    }

    /// Runs the virtualized cohort bucketing.
    ///
    /// # Panics
    /// Never for well-formed input: the demo program is straight-line and reads
    /// exactly [`DEMO_COHORT_INPUTS`] slots.
    #[must_use]
    pub fn run(&self, device_hi: u64, device_lo: u64, salt: u64) -> u64 {
        interp::run_ir(&self.program, &[device_hi, device_lo, salt])
            .expect("demo cohort program runs")
    }
}

/// Computes the device cohort bucket, selecting the execution strategy by
/// `strength`.
///
/// * `OFF`/`LOW`/`MEDIUM` → the native routine [`demo_cohort_native`].
/// * `HIGH` → the virtualized program, built per `seed`.
///
/// The result is identical in every case (behaviour-preserving). `seed` is
/// ignored unless `strength` virtualizes.
#[must_use]
pub fn cohort_bucket(
    strength: ObfuscationStrength,
    seed: &BuildSeed,
    device_hi: u64,
    device_lo: u64,
    salt: u64,
) -> u64 {
    if strength.virtualizes() {
        VirtualCohort::build(seed).run(device_hi, device_lo, salt)
    } else {
        demo_cohort_native(device_hi, device_lo, salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64 — deterministic, dependency-free.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn default_strength_is_off_and_does_not_virtualize() {
        assert_eq!(ObfuscationStrength::default(), ObfuscationStrength::Off);
        for s in [
            ObfuscationStrength::Off,
            ObfuscationStrength::Low,
            ObfuscationStrength::Medium,
        ] {
            assert!(!s.virtualizes(), "{s:?} must not virtualize");
        }
        assert!(ObfuscationStrength::High.virtualizes());
    }

    #[test]
    fn every_strength_yields_the_native_result() {
        let seed = BuildSeed::from_u64(0xB0CC_E70F_1234_5678);
        let mut rng = Rng(0x0DD0_FE11);
        for _ in 0..5000 {
            let (hi, lo, salt) = (rng.next(), rng.next(), rng.next());
            let want = demo_cohort_native(hi, lo, salt);
            for s in [
                ObfuscationStrength::Off,
                ObfuscationStrength::Low,
                ObfuscationStrength::Medium,
                ObfuscationStrength::High,
            ] {
                assert_eq!(cohort_bucket(s, &seed, hi, lo, salt), want, "{s:?}");
            }
        }
    }

    #[test]
    fn high_strength_actually_runs_the_vm_path() {
        // Build the virtualized form and confirm it matches native — i.e. the
        // HIGH path is exercised, not silently bypassed.
        let seed = BuildSeed::from_u64(0x7711_2233_4455_6677);
        let vc = VirtualCohort::build(&seed);
        let mut rng = Rng(0xFEED_FACE);
        for _ in 0..2000 {
            let (hi, lo, salt) = (rng.next(), rng.next(), rng.next());
            assert_eq!(vc.run(hi, lo, salt), demo_cohort_native(hi, lo, salt));
        }
    }
}
