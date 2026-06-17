//! Compile-time string-literal obfuscation for the trust core.
//!
//! Sensitive constants — the detection-module taxonomy, internal logic/error
//! strings — would otherwise sit in plaintext in the shipped native artifact's
//! `.rodata`, where a trivial `strings`/`grep` reveals what the SDK detects and
//! how it reasons. This module keeps those literals out of `.rodata`: the
//! plaintext is consumed only at **compile time** to produce an obfuscated byte
//! array, and the original bytes are reconstructed on a short-lived **stack**
//! buffer on first use.
//!
//! # Design
//!
//! - **In-repo, zero new dependencies.** A small const-evaluable XOR over a
//!   per-literal keystream (see [`keystream_byte`]). No third-party crate, no
//!   supply-chain surface.
//! - **Deterministic.** The keystream seed ([`seed_of`]) is a pure function of
//!   the literal's bytes, so identical sources produce byte-identical artifacts.
//!   There is no per-build randomness, which preserves the reproducible
//!   `build_hash` discipline the build-proof relies on.
//! - **Byte-exact round-trip.** Deobfuscation is the same XOR in reverse, so the
//!   reconstructed bytes are *identical* to the original — safe even for
//!   constants whose exact bytes matter.
//! - **Opt-in / fail-safe.** Everything is gated behind the `obfuscate-strings`
//!   cargo feature (default **off**). With the feature off, [`obfstr!`] and
//!   [`obfstr_string!`] expand to the bare literal, so the default debuggable
//!   build is byte-for-byte the code it always was.
//! - **Defense-in-depth, not secrecy.** This raises the bar against casual
//!   static inspection of the artifact; it is *not* a cryptographic secret
//!   (the algorithm and per-literal seed are derivable). High-value secrets
//!   continue to live behind the crypto layer, never as obfuscated literals.
//!
//! This is the native-object analogue of the Phase 5.1 *bytecode* string
//! transforms; it operates on the Rust trust core that compiles into the
//! Android `.so` / Apple static lib.

/// Crate-wide base seed folded into every per-literal seed. Re-keying every
/// obfuscated literal is a one-line change here; the result stays deterministic
/// (and therefore reproducible) because it depends only on source bytes.
const BASE_SEED: u64 = 0x6B73_6561_6C5F_3532; // b"kseal_52"

/// FNV-1a hash of `bytes`, folded with [`BASE_SEED`], used to seed the
/// keystream for a single literal. `const fn` so it is evaluated at compile
/// time inside [`obfstr!`]; never executed on the literal at run time.
///
/// A degenerate all-zero result is remapped to a fixed odd constant so the
/// keystream never collapses to the identity transform.
#[allow(dead_code)] // invoked by obfstr!/obfstr_string! under `obfuscate-strings`, and by tests.
pub(crate) const fn seed_of(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325 ^ BASE_SEED; // FNV-1a offset basis
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3); // FNV-1a prime
        i += 1;
    }
    if hash == 0 {
        0x9e37_79b9_7f4a_7c15
    } else {
        hash
    }
}

/// Position-dependent keystream byte for `seed` at index `i`.
///
/// A SplitMix64-style avalanche of `seed + i·φ` so adjacent positions differ
/// unpredictably; this is what keeps the obfuscated bytes from preserving the
/// plaintext's structure (and prevents the plaintext appearing as a substring).
#[allow(dead_code)] // invoked by obfstr!/obfstr_string! under `obfuscate-strings`, and by tests.
pub(crate) const fn keystream_byte(seed: u64, i: usize) -> u8 {
    let mut z = seed
        .wrapping_add((i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    (z & 0xff) as u8
}

/// Obfuscates `plain` into a fixed-size array at compile time (the bytes that
/// end up in `.rodata`). Call sites always pass `plain.len() == N`; the bounds
/// check is defensive and folds away during const evaluation.
#[allow(dead_code)] // invoked by obfstr!/obfstr_string! under `obfuscate-strings`, and by tests.
pub(crate) const fn obfuscate_const<const N: usize>(plain: &[u8], seed: u64) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let p = if i < plain.len() { plain[i] } else { 0 };
        out[i] = p ^ keystream_byte(seed, i);
        i += 1;
    }
    out
}

/// A short-lived, stack-resident holder for a deobfuscated literal.
///
/// The reconstructed plaintext lives only for as long as the value is in scope
/// and is scrubbed on [`Drop`]. [`obfstr!`] borrows it for a single expression;
/// [`obfstr_string!`] copies it into an owned `String` and drops it immediately.
#[allow(dead_code)] // constructed by obfstr!/obfstr_string! under `obfuscate-strings`, and by tests.
pub(crate) struct ObfBuffer<const N: usize> {
    buf: [u8; N],
}

#[allow(dead_code)] // see struct note.
impl<const N: usize> ObfBuffer<N> {
    /// Reconstructs the original bytes from `obf` using the same keystream the
    /// obfuscation used. The XOR is its own inverse, so this is byte-exact.
    #[inline]
    pub(crate) fn deobfuscate(obf: &[u8; N], seed: u64) -> Self {
        let mut buf = [0u8; N];
        let mut i = 0;
        while i < N {
            buf[i] = obf[i] ^ keystream_byte(seed, i);
            i += 1;
        }
        Self { buf }
    }

    /// Borrows the reconstructed plaintext as `&str`.
    ///
    /// The bytes were a valid `&str` literal before obfuscation and the XOR
    /// round-trips exactly, so they are valid UTF-8 by construction.
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf)
            .expect("obfuscated literal must round-trip to valid UTF-8")
    }

    /// Copies the reconstructed plaintext into an owned `String`, then drops
    /// (and scrubs) the stack buffer. Used where the value must outlive the
    /// current expression.
    #[inline]
    pub(crate) fn into_string(self) -> String {
        self.as_str().to_owned()
    }
}

impl<const N: usize> Drop for ObfBuffer<N> {
    fn drop(&mut self) {
        // Best-effort scrub so the reconstructed plaintext does not linger on
        // the stack after use. `#![forbid(unsafe_code)]` rules out a volatile
        // write, so `black_box` is used to keep the overwrite from being
        // optimized away.
        for b in &mut self.buf {
            *b = 0;
        }
        core::hint::black_box(&self.buf);
    }
}

/// Returns a sensitive string literal as `&str`, keeping its plaintext out of
/// the artifact's `.rodata` when built with `--features obfuscate-strings`.
///
/// With the feature **off** (the default) this expands to the bare literal, so
/// the standard build is unchanged and fully debuggable.
///
/// The returned `&str` borrows a stack buffer that lives until the end of the
/// enclosing statement — use it inline (comparisons, `format!`, function
/// arguments). To store the value, use [`obfstr_string!`].
#[cfg(feature = "obfuscate-strings")]
macro_rules! obfstr {
    ($s:literal) => {
        ({
            const SEED: u64 = $crate::obfuscate::seed_of($s.as_bytes());
            const OBF: [u8; $s.len()] = $crate::obfuscate::obfuscate_const($s.as_bytes(), SEED);
            $crate::obfuscate::ObfBuffer::<{ $s.len() }>::deobfuscate(&OBF, SEED)
        })
        .as_str()
    };
}

/// See [`obfstr!`]. With the feature off this is the bare literal.
#[cfg(not(feature = "obfuscate-strings"))]
macro_rules! obfstr {
    ($s:literal) => {
        $s
    };
}

/// Like [`obfstr!`] but returns an owned `String`, for values that must outlive
/// the current expression (struct fields, error payloads).
#[cfg(feature = "obfuscate-strings")]
macro_rules! obfstr_string {
    ($s:literal) => {
        ({
            const SEED: u64 = $crate::obfuscate::seed_of($s.as_bytes());
            const OBF: [u8; $s.len()] = $crate::obfuscate::obfuscate_const($s.as_bytes(), SEED);
            $crate::obfuscate::ObfBuffer::<{ $s.len() }>::deobfuscate(&OBF, SEED)
        })
        .into_string()
    };
}

/// See [`obfstr_string!`]. With the feature off this is `String::from(literal)`.
#[cfg(not(feature = "obfuscate-strings"))]
macro_rules! obfstr_string {
    ($s:literal) => {
        ::std::string::String::from($s)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runtime twin of [`obfuscate_const`], for property tests over arbitrary
    /// lengths. Must agree byte-for-byte with the const path.
    fn obfuscate_bytes(plain: &[u8], seed: u64) -> Vec<u8> {
        plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ keystream_byte(seed, i))
            .collect()
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return needle.is_empty();
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Every literal the crate actually obfuscates. The round-trip assertion
    /// below is the mandatory correctness gate; keep this list in sync with the
    /// call sites in `config.rs` and `policy.rs`.
    const APPLIED_LITERALS: &[&str] = &[
        // policy.rs — detection-module taxonomy
        "root",
        "jailbreak",
        "emulator",
        "simulator",
        "debugger",
        "hooking",
        "tamper",
        "app_integrity",
        "network_mitm",
        "environment",
        "attestation",
        // config.rs — internal logic/error string
        "config signature verification failed",
    ];

    #[test]
    fn const_and_runtime_paths_agree() {
        // The bytes baked into `.rodata` (const path) must equal the runtime
        // twin used by the property tests, so the tests below describe reality.
        const S: &str = "network_mitm";
        let seed = seed_of(S.as_bytes());
        let konst: [u8; 12] = obfuscate_const(S.as_bytes(), seed);
        assert_eq!(konst.to_vec(), obfuscate_bytes(S.as_bytes(), seed));
    }

    #[test]
    fn obfuscated_bytes_never_contain_plaintext() {
        // The exact property we care about: the bytes that land in `.rodata`
        // do not contain the plaintext as a substring.
        for &s in APPLIED_LITERALS {
            if s.len() < 3 {
                continue; // too short for a meaningful substring claim
            }
            let seed = seed_of(s.as_bytes());
            let obf = obfuscate_bytes(s.as_bytes(), seed);
            assert!(
                !contains_subslice(&obf, s.as_bytes()),
                "plaintext leaked into obfuscated bytes for {s:?}"
            );
        }
    }

    #[test]
    fn runtime_round_trip_is_byte_exact() {
        for &s in APPLIED_LITERALS {
            let seed = seed_of(s.as_bytes());
            let obf = obfuscate_bytes(s.as_bytes(), seed);
            let back: Vec<u8> = obf
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ keystream_byte(seed, i))
                .collect();
            assert_eq!(back, s.as_bytes(), "round-trip mismatch for {s:?}");
        }
    }

    #[test]
    fn obf_buffer_round_trips_and_scrubs() {
        const S: &str = "config signature verification failed";
        let seed = seed_of(S.as_bytes());
        let obf: [u8; 36] = obfuscate_const(S.as_bytes(), seed);
        assert_eq!(S.len(), 36);
        let buf = ObfBuffer::<36>::deobfuscate(&obf, seed);
        assert_eq!(buf.as_str(), S);
        assert_eq!(buf.into_string(), S);
    }

    /// The mandatory gate: every literal exposed through the macros decrypts to
    /// its exact original bytes. Runs in both feature modes — with the feature
    /// off it confirms the call sites still compile and equal the literal; with
    /// `--features obfuscate-strings` it exercises real deobfuscation.
    #[test]
    fn macro_round_trip_matches_literal() {
        assert_eq!(obfstr!("root"), "root");
        assert_eq!(obfstr!("jailbreak"), "jailbreak");
        assert_eq!(obfstr!("emulator"), "emulator");
        assert_eq!(obfstr!("simulator"), "simulator");
        assert_eq!(obfstr!("debugger"), "debugger");
        assert_eq!(obfstr!("hooking"), "hooking");
        assert_eq!(obfstr!("tamper"), "tamper");
        assert_eq!(obfstr!("app_integrity"), "app_integrity");
        assert_eq!(obfstr!("network_mitm"), "network_mitm");
        assert_eq!(obfstr!("environment"), "environment");
        assert_eq!(obfstr!("attestation"), "attestation");
        assert_eq!(
            obfstr!("config signature verification failed"),
            "config signature verification failed"
        );
        assert_eq!(
            obfstr_string!("config signature verification failed"),
            "config signature verification failed".to_owned()
        );
    }

    #[test]
    fn macro_is_usable_inline() {
        // Exercises the borrow-for-one-statement contract in real positions.
        let module = "network_mitm";
        assert!(module == obfstr!("network_mitm"));
        let msg = format!("err: {}", obfstr!("hooking"));
        assert_eq!(msg, "err: hooking");
    }

    #[test]
    fn empty_and_unicode_round_trip() {
        // Edge cases the macro must not corrupt.
        assert_eq!(obfstr!(""), "");
        assert_eq!(obfstr!("ⓤnᵢ𝄪code"), "ⓤnᵢ𝄪code");
    }
}
