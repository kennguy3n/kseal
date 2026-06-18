//! # Phase 5.3 DECISION SPIKE — selective code virtualization (NOT production)
//!
//! This module is a **bounded proof-of-concept** that demonstrates the
//! code-virtualization technique end-to-end on one representative function, so
//! the team can make an evidence-backed go/no-go decision. It is compiled only
//! under the default-off `vm-spike` cargo feature and is deliberately isolated:
//!
//! * It does **not** touch the real trust, crypto, kill-switch, proof-signing,
//!   risk, or FFI paths. The function it virtualizes ([`isa::native_tag_mix`])
//!   is a self-contained toy mixer invented purely for measurement.
//! * It adds **nothing** to the public C ABI.
//! * With the feature off, the standard build is byte-for-byte unchanged.
//!
//! See `docs/virtualization-tier-decision.md` for the threat model, layering,
//! perf/size budget (using the numbers this spike measures), the
//! crash-symbolication tradeoff, and the GO/NO-GO recommendation.
//!
//! ## What the spike demonstrates
//!
//! 1. **A tiny custom bytecode VM + dispatch loop** ([`isa`], [`interp`]): a
//!    10-opcode register machine that runs a hand-lowered program.
//! 2. **Byte-identical behavior**: the virtualized program reproduces the native
//!    function exactly over randomized inputs (see tests).
//! 3. **Per-build polymorphism** ([`encode`]): opcode/register permutations and
//!    a keystream are derived from an explicit [`encode::BuildSeed`], so two
//!    seeds yield different bytecode while a fixed seed stays reproducible.
//! 4. **The crash-symbolication mitigation** ([`retrace`]): an encrypted
//!    VM-pc → source-site map plus a symbolicator that resolves a captured crash
//!    frame — and yields nothing to anyone without the build key.
//! 5. **Measured cost**: a harness ([`measure`]) reporting native-vs-virtualized
//!    throughput and the code-size delta.

pub mod encode;
pub mod interp;
pub mod ir;
pub mod isa;
pub mod retrace;
pub mod strength;

#[doc(inline)]
pub use encode::{decode_with_seed, encode_with_seed, BuildSeed};
#[doc(inline)]
pub use interp::{run, run_ir, VmError, VmFrame};
#[doc(inline)]
pub use ir::{lower, Expr, LowerError};
#[doc(inline)]
pub use isa::{lower_tag_mix, native_tag_mix, LoweredProgram, Program};
#[doc(inline)]
pub use retrace::{encrypt_map, ResolvedSite, Symbolicator};
#[doc(inline)]
pub use strength::ObfuscationStrength;

/// The shippable artifacts a virtualized build would emit for one function:
/// the polymorphic bytecode (linked into the binary) and the encrypted retrace
/// map (kept private, out of band).
#[derive(Debug, Clone)]
pub struct SpikeArtifacts {
    /// Per-build-polymorphic encoded bytecode for the function.
    pub bytecode: Vec<u8>,
    /// Encrypted de-virtualization / retrace map for the function.
    pub retrace_map: Vec<u8>,
}

impl SpikeArtifacts {
    /// Builds the bytecode + encrypted retrace map for the demo function under
    /// `seed`.
    #[must_use]
    pub fn build(seed: &BuildSeed) -> Self {
        let lowered = lower_tag_mix();
        let build_hash = retrace::build_hash_from_seed(seed);
        SpikeArtifacts {
            bytecode: encode_with_seed(&lowered.program, seed),
            retrace_map: encrypt_map(&lowered.retrace, seed, &build_hash),
        }
    }

    /// Size of the encoded bytecode in bytes.
    #[must_use]
    pub fn bytecode_size(&self) -> usize {
        self.bytecode.len()
    }

    /// Size of the encrypted retrace map in bytes.
    #[must_use]
    pub fn retrace_map_size(&self) -> usize {
        self.retrace_map.len()
    }
}

/// Convenience: run the demo function virtualized — encode under `seed`, decode,
/// and interpret — returning the same value [`native_tag_mix`] would.
///
/// # Errors
/// Returns an error string if encoding/decoding or interpretation faults; for
/// the well-formed demo program this never happens.
pub fn run_virtualized(seed: &BuildSeed, input: &[u8], domain: u64) -> Result<u64, String> {
    let lowered = lower_tag_mix();
    let bytes = encode_with_seed(&lowered.program, seed);
    let program = decode_with_seed(&bytes, seed).map_err(|e| format!("decode: {e:?}"))?;
    interp::run(&program, input, domain).map_err(|e| format!("run: {e:?}"))
}

/// A lightweight measurement harness (no extra dependencies) that the perf test
/// prints and the design doc cites.
pub mod measure {
    use super::{encode_with_seed, isa, BuildSeed, SpikeArtifacts};
    use std::hint::black_box;
    use std::time::Instant;

    /// The result of a throughput + size measurement run.
    #[derive(Debug, Clone)]
    pub struct Report {
        /// Average native nanoseconds per call.
        pub native_ns: f64,
        /// Average virtualized nanoseconds per call.
        pub vm_ns: f64,
        /// `vm_ns / native_ns` — the perf tax.
        pub ratio: f64,
        /// Size (bytes) of the function's machine code is measured offline; this
        /// is the on-disk size of the polymorphic bytecode that replaces it.
        pub bytecode_size: usize,
        /// Size (bytes) of the encrypted retrace map for the function.
        pub retrace_map_size: usize,
        /// Number of decoded instructions in the program.
        pub instr_count: usize,
        /// Bytes of input used per call in the throughput loop.
        pub input_len: usize,
    }

    /// Runs a native-vs-virtualized throughput comparison plus size accounting.
    ///
    /// Timing is informational (it is printed, never asserted) so it never makes
    /// CI flaky; the test that calls this asserts only behavioral equality.
    #[must_use]
    pub fn run(iterations: u32, input_len: usize) -> Report {
        let seed = BuildSeed::from_u64(0xC0FF_EE12_3456_789A);
        let lowered = isa::lower_tag_mix();
        // Decode once (as a shipped build would, before the hot path).
        let program = super::decode_with_seed(&encode_with_seed(&lowered.program, &seed), &seed)
            .expect("demo program decodes");

        let mut input = vec![0u8; input_len];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        // Warm up.
        for d in 0..1000u64 {
            black_box(isa::native_tag_mix(black_box(&input), d));
            let _ = black_box(super::interp::run(&program, black_box(&input), d));
        }

        let t0 = Instant::now();
        let mut acc = 0u64;
        for d in 0..iterations {
            acc ^= isa::native_tag_mix(black_box(&input), u64::from(d));
        }
        black_box(acc);
        let native_ns = t0.elapsed().as_nanos() as f64 / f64::from(iterations);

        let t1 = Instant::now();
        let mut acc2 = 0u64;
        for d in 0..iterations {
            acc2 ^= super::interp::run(&program, black_box(&input), u64::from(d))
                .expect("vm runs");
        }
        black_box(acc2);
        let vm_ns = t1.elapsed().as_nanos() as f64 / f64::from(iterations);

        let artifacts = SpikeArtifacts::build(&seed);
        Report {
            native_ns,
            vm_ns,
            ratio: vm_ns / native_ns.max(f64::MIN_POSITIVE),
            bytecode_size: artifacts.bytecode_size(),
            retrace_map_size: artifacts.retrace_map_size(),
            instr_count: program.instrs.len(),
            input_len,
        }
    }

    /// Size + throughput accounting for the **IR-compiled** demo cohort routine
    /// (Task A/C), as opposed to the hand-lowered routine measured by [`run`].
    /// This is the number the GO doc cites for the maintained compiler path.
    #[derive(Debug, Clone)]
    pub struct CohortReport {
        /// Average native nanoseconds per call.
        pub native_ns: f64,
        /// Average virtualized nanoseconds per call.
        pub vm_ns: f64,
        /// `vm_ns / native_ns` — the perf tax.
        pub ratio: f64,
        /// Size (bytes) of the polymorphic bytecode for the lowered routine.
        pub bytecode_size: usize,
        /// Size (bytes) of the encrypted+authenticated retrace map.
        pub retrace_map_size: usize,
        /// Number of decoded instructions the compiler emitted.
        pub instr_count: usize,
    }

    /// Measures the IR-compiled demo cohort routine end-to-end: lower → encode →
    /// decode → run, versus the native reference.
    #[must_use]
    pub fn run_cohort(iterations: u32) -> CohortReport {
        use super::ir::{self, demo_cohort_expr, demo_cohort_native, DEMO_COHORT_INPUTS};
        use super::retrace::{build_hash_from_seed, encrypt_map};

        let seed = BuildSeed::from_u64(0x0C01_D9A7_E5EE_D001);
        let lowered = ir::lower("demo_cohort", DEMO_COHORT_INPUTS, &demo_cohort_expr())
            .expect("demo cohort lowers");
        let bytecode = encode_with_seed(&lowered.program, &seed);
        let program = super::decode_with_seed(&bytecode, &seed).expect("demo cohort decodes");
        let retrace_map =
            encrypt_map(&lowered.retrace, &seed, &build_hash_from_seed(&seed));

        for d in 0..1000u64 {
            black_box(demo_cohort_native(black_box(d), d ^ 0x55, d.wrapping_mul(7)));
            let _ = black_box(super::interp::run_ir(
                &program,
                black_box(&[d, d ^ 0x55, d.wrapping_mul(7)]),
            ));
        }

        let t0 = Instant::now();
        let mut acc = 0u64;
        for d in 0..u64::from(iterations) {
            acc ^= demo_cohort_native(black_box(d), d ^ 0x55, d.wrapping_mul(7));
        }
        black_box(acc);
        let native_ns = t0.elapsed().as_nanos() as f64 / f64::from(iterations);

        let t1 = Instant::now();
        let mut acc2 = 0u64;
        for d in 0..u64::from(iterations) {
            acc2 ^= super::interp::run_ir(&program, black_box(&[d, d ^ 0x55, d.wrapping_mul(7)]))
                .expect("vm runs");
        }
        black_box(acc2);
        let vm_ns = t1.elapsed().as_nanos() as f64 / f64::from(iterations);

        CohortReport {
            native_ns,
            vm_ns,
            ratio: vm_ns / native_ns.max(f64::MIN_POSITIVE),
            bytecode_size: bytecode.len(),
            retrace_map_size: retrace_map.len(),
            instr_count: program.instrs.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny deterministic SplitMix64 PRNG so the property test needs no rng dep.
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
    fn virtualized_is_byte_identical_to_native_over_random_inputs() {
        let lowered = lower_tag_mix();
        let seed = BuildSeed::from_u64(0xABCD_1234);
        let program =
            decode_with_seed(&encode_with_seed(&lowered.program, &seed), &seed).unwrap();

        let mut rng = Rng(0xDEAD_BEEF_0BAD_F00D);
        for _ in 0..4000 {
            let len = (rng.next() % 65) as usize; // 0..=64 bytes
            let mut input = vec![0u8; len];
            for b in &mut input {
                *b = (rng.next() & 0xff) as u8;
            }
            let domain = rng.next();
            let want = native_tag_mix(&input, domain);
            let got = interp::run(&program, &input, domain).unwrap();
            assert_eq!(got, want, "len={len} domain={domain:#x}");
        }
    }

    #[test]
    fn polymorphism_two_seeds_differ_yet_both_compute_correctly() {
        let lowered = lower_tag_mix();
        let seed_a = BuildSeed::from_u64(0xAAAA);
        let seed_b = BuildSeed::from_u64(0xBBBB);

        let bytes_a = encode_with_seed(&lowered.program, &seed_a);
        let bytes_b = encode_with_seed(&lowered.program, &seed_b);
        assert_ne!(bytes_a, bytes_b, "two builds must differ");

        // Deterministic per seed (reproducible build_hash discipline).
        assert_eq!(bytes_a, encode_with_seed(&lowered.program, &seed_a));

        let input = b"polymorphic-build-test";
        let domain = 0x0123_4567_89AB_CDEF;
        let want = native_tag_mix(input, domain);
        assert_eq!(run_virtualized(&seed_a, input, domain).unwrap(), want);
        assert_eq!(run_virtualized(&seed_b, input, domain).unwrap(), want);
    }

    #[test]
    fn captured_crash_frame_resolves_to_the_right_source_site() {
        let lowered = lower_tag_mix();
        let seed = BuildSeed::from_u64(0x5151_5151);
        let build_hash = retrace::build_hash_from_seed(&seed);
        let encrypted = encrypt_map(&lowered.retrace, &seed, &build_hash);

        // Force a real, deterministic fault inside the dispatch loop by starving
        // the step budget, then symbolicate the captured frame.
        let program = lowered.program.clone();
        let err = interp::run_with_fuel(&program, b"crash-here", 9, 5).unwrap_err();
        let sym = Symbolicator::open(&encrypted, &seed, &build_hash).unwrap();
        let site = sym
            .resolve(err.frame)
            .expect("captured pc must resolve through the private map");
        assert_eq!(site.function, "native_tag_mix");

        // And nobody without the build key can read the map.
        assert!(Symbolicator::open(&encrypted, &BuildSeed::from_u64(0x9999), &build_hash).is_err());
    }

    #[test]
    fn perf_and_size_report_prints_numbers() {
        // Sweep a few input sizes; small payloads model a "cold gate".
        println!("--- vmspike measurement (informational; release numbers in doc) ---");
        let mut last = None;
        for &len in &[0usize, 1, 8, 32, 256] {
            let report = measure::run(100_000, len);
            println!(
                "len={:>3}  native={:>8.2}ns  vm={:>9.2}ns  tax={:>6.1}x  bytecode={}B  retrace={}B  instrs={}",
                report.input_len,
                report.native_ns,
                report.vm_ns,
                report.ratio,
                report.bytecode_size,
                report.retrace_map_size,
                report.instr_count,
            );
            last = Some(report);
        }
        // Behavior assertions only — never timing — so CI stays stable.
        let report = last.unwrap();
        assert!(report.bytecode_size > 0);
        assert!(report.retrace_map_size > 0);
        assert!(report.instr_count >= 10);

        // IR-compiled demo cohort (the maintained-compiler path).
        let cohort = measure::run_cohort(100_000);
        println!(
            "cohort   native={:>8.2}ns  vm={:>9.2}ns  tax={:>6.1}x  bytecode={}B  retrace={}B  instrs={}",
            cohort.native_ns,
            cohort.vm_ns,
            cohort.ratio,
            cohort.bytecode_size,
            cohort.retrace_map_size,
            cohort.instr_count,
        );
        assert!(cohort.bytecode_size > 0);
        assert!(cohort.retrace_map_size > 0);
        assert!(cohort.instr_count > 0);
    }
}
