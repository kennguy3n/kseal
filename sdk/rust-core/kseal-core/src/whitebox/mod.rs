//! # Phase 6.1 SPIKE — white-box cryptography for the proof key (NOT production)
//!
//! Some devices report `SECURE_HW_MISSING`: there is no hardware-backed
//! keystore, so the per-instance proof key would otherwise sit as raw bytes in
//! the process image and the shipped `.so`/dylib. This module is a **bounded
//! proof-of-concept** that evaluates a *white-box* representation of the
//! proof-key path, where the key is baked into **encoded lookup tables** at
//! build time so a static dump of the binary does not reveal it.
//!
//! It is compiled only under the default-off `whitebox-spike` cargo feature and
//! is deliberately isolated:
//!
//! * It does **not** replace or alter the production crypto path. The shipped
//!   request proof is still produced by [`crate::crypto::generate_request_proof`]
//!   (`hmac` + `sha2`); this module reproduces the *same* tag a different way.
//! * It adds **nothing** to the public C ABI.
//! * With the feature off, the standard build is byte-for-byte unchanged.
//!
//! See `docs/whitebox-crypto-decision.md` for the threat model, where it
//! applies, the measured perf/size budget (using the numbers this spike
//! measures), the build/vendor posture, and the GO/NO-GO recommendation.
//!
//! ## What the spike demonstrates
//!
//! 1. **Encoded key tables** ([`tables`]): the two `HMAC-SHA256` key blocks are
//!    stored as per-byte encoded values plus inverse permutation tables,
//!    generated inside `const fn`s so the raw key is consumed at compile time
//!    and never emitted into the binary.
//! 2. **Exact parity** ([`whitebox_request_proof`], [`whitebox_hmac_sha256`]):
//!    the white-box path computes the **identical** proof HMAC tag as the
//!    production path — proven against the project's golden vector, byte-for-
//!    byte. This is the Go↔device parity acceptance criterion: the device-side
//!    white-box result equals what the Go server independently expects.
//! 3. **Measured cost** ([`measure`]): the table size in bytes and the per-tag
//!    latency vs the standard path, for the design doc's perf budget.
//!
//! ## Honest scope (see the design doc for the full treatment)
//!
//! This self-contained spike defends **static** extraction: the contiguous key
//! is absent from the shipped artifact and is recoverable only by understanding
//! and composing the encoded tables. It does **not** achieve a fully-encoded
//! data flow — the key block is transiently reconstructed in memory at use, so a
//! determined *dynamic* attacker (or a grey-box DCA/DFA adversary) can still
//! lift it. Raising that bar requires white-boxing the SHA-256 compression
//! itself or a vendor toolchain, which is the productionization question the
//! design doc answers.

mod mac;
mod tables;

pub use mac::whitebox_hmac_sha256;
pub use tables::WHITEBOX_TABLE_BYTES;

use crate::proto::RequestProof;

/// Domain-separation tag for the request-proof preimage — identical to
/// `crypto::PROOF_DOMAIN`. Duplicated here (not imported) so the spike stays
/// fully self-contained behind its feature; the parity tests fail loudly if it
/// ever diverges from the production layout.
const PROOF_DOMAIN: &[u8] = b"kseal/v1/request-proof";

/// Total size in bytes of the baked white-box tables.
#[must_use]
pub fn table_size_bytes() -> usize {
    WHITEBOX_TABLE_BYTES
}

/// Appends a 4-byte big-endian length prefix followed by `field`, mirroring
/// `crypto::push_lp` — including its debug-asserted `u32` length guard, so the
/// spike preimage layout matches the production contract exactly.
fn push_lp(buf: &mut Vec<u8>, field: &[u8]) {
    debug_assert!(
        field.len() <= u32::MAX as usize,
        "length-prefixed field exceeds u32 prefix",
    );
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Builds the canonical, domain-separated, length-prefixed proof preimage,
/// mirroring `crypto::proof_preimage` exactly:
///
/// `u32_be(len(DOMAIN)) || DOMAIN || u32_be(len(token_id)) || token_id ||
///  u32_be(len(request_hash)) || request_hash || u32_be(len(nonce)) || nonce ||
///  i64_be(seq)`.
fn proof_preimage(token_id: &str, request_hash: &[u8], nonce: &[u8], seq: i64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        4 * core::mem::size_of::<u32>()
            + PROOF_DOMAIN.len()
            + token_id.len()
            + request_hash.len()
            + nonce.len()
            + core::mem::size_of::<i64>(),
    );
    push_lp(&mut msg, PROOF_DOMAIN);
    push_lp(&mut msg, token_id.as_bytes());
    push_lp(&mut msg, request_hash);
    push_lp(&mut msg, nonce);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg
}

/// Generates a [`RequestProof`] using the **white-box** proof-key tables.
///
/// The returned proof — including its `app_instance_signature` HMAC tag — is
/// byte-for-byte identical to
/// `crypto::generate_request_proof(proof_key, token_id, request_hash, nonce,
/// seq)` for the spike's pinned proof key. This is the end-to-end parity demo:
/// the white-box device path and the standard path are interchangeable, so the
/// Go server's independent verification succeeds against either.
#[must_use]
pub fn whitebox_request_proof(
    token_id: &str,
    request_hash: &[u8],
    nonce: &[u8],
    seq: i64,
) -> RequestProof {
    let tag = whitebox_hmac_sha256(&proof_preimage(token_id, request_hash, nonce, seq));
    RequestProof {
        trust_token_id: token_id.to_string(),
        request_hash: request_hash.to_vec(),
        nonce: nonce.to_vec(),
        app_instance_signature: tag.to_vec(),
        monotonic_sequence: seq,
    }
}

/// A lightweight measurement harness (no extra dependencies) that the perf test
/// prints and the design doc cites.
pub mod measure {
    use crate::crypto;
    use std::hint::black_box;
    use std::time::Instant;

    /// A non-secret, throwaway key of the same length (23 bytes) as the spike's
    /// proof key, used only to time the standard path. `HMAC-SHA256` latency is
    /// independent of the key's contents, so this is representative while keeping
    /// the real key out of the (always-compiled) measurement code — and thus out
    /// of any static dump of the artifact.
    const TIMING_KEY: &[u8] = b"whitebox-spike-timing!!";

    /// The result of a per-tag latency + table-size measurement.
    #[derive(Debug, Clone)]
    pub struct Report {
        /// Average standard `HMAC-SHA256` nanoseconds per tag.
        pub std_ns: f64,
        /// Average white-box nanoseconds per tag.
        pub wb_ns: f64,
        /// `wb_ns / std_ns` — the per-op tax.
        pub ratio: f64,
        /// Size in bytes of the baked white-box tables.
        pub table_bytes: usize,
        /// Message length (bytes) used in the timing loop.
        pub msg_len: usize,
    }

    /// Runs a standard-vs-white-box per-tag latency comparison plus table-size
    /// accounting.
    ///
    /// Timing is informational (it is printed, never asserted) so it never makes
    /// CI flaky; the parity tests assert byte-for-byte equality separately.
    #[must_use]
    pub fn run(iterations: u32, msg_len: usize) -> Report {
        let msg: Vec<u8> = (0..msg_len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect();

        for _ in 0..2000 {
            black_box(crypto::hmac_sha256(TIMING_KEY, black_box(&msg)));
            black_box(super::whitebox_hmac_sha256(black_box(&msg)));
        }

        let t0 = Instant::now();
        let mut acc = 0u8;
        for _ in 0..iterations {
            acc ^= crypto::hmac_sha256(TIMING_KEY, black_box(&msg))[0];
        }
        black_box(acc);
        let std_ns = t0.elapsed().as_nanos() as f64 / f64::from(iterations);

        let t1 = Instant::now();
        let mut acc2 = 0u8;
        for _ in 0..iterations {
            acc2 ^= super::whitebox_hmac_sha256(black_box(&msg))[0];
        }
        black_box(acc2);
        let wb_ns = t1.elapsed().as_nanos() as f64 / f64::from(iterations);

        Report {
            std_ns,
            wb_ns,
            ratio: wb_ns / std_ns.max(f64::MIN_POSITIVE),
            table_bytes: super::WHITEBOX_TABLE_BYTES,
            msg_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    /// The spike's pinned proof key (== the golden proof-HMAC vector key).
    const KEY: &[u8] = b"kseal-test-instance-key";
    /// Golden proof-HMAC tag from `crypto::proof_preimage_exact_byte_layout`.
    const GOLDEN_TAG_HEX: &str =
        "718bb06df45dc4bbc5bf483bd65acf7609429966adba8baff66fa965857ebd0d";

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// THE key deliverable: the white-box path computes the exact same proof
    /// HMAC tag as the production path AND as the shipped golden vector,
    /// byte-for-byte.
    #[test]
    fn whitebox_proof_tag_equals_standard_and_golden() {
        // The golden vector inputs from crypto.rs.
        let token_id = "tok";
        let request_hash = [0x01u8, 0x02, 0x03, 0x04];
        let nonce = [0xAAu8, 0xBB];
        let seq = 1i64;

        let standard =
            crypto::generate_request_proof(KEY, token_id, &request_hash, &nonce, seq);
        let whitebox = whitebox_request_proof(token_id, &request_hash, &nonce, seq);

        // Tag parity (the proof HMAC tag).
        assert_eq!(
            whitebox.app_instance_signature, standard.app_instance_signature,
            "white-box tag must equal the standard HMAC tag"
        );
        // Full RequestProof parity (the white-box path is a drop-in).
        assert_eq!(
            whitebox, standard,
            "white-box RequestProof must equal the standard path"
        );
        // Golden-vector parity, byte-for-byte.
        assert_eq!(
            to_hex(&whitebox.app_instance_signature),
            GOLDEN_TAG_HEX,
            "white-box tag must equal the golden proof-HMAC vector"
        );
    }

    /// White-box == standard over many message lengths/contents (the parity is
    /// the construction, not a single fixed input).
    #[test]
    fn whitebox_hmac_matches_standard_over_random_messages() {
        // SplitMix64 — deterministic, no rng dep.
        let mut state = 0x0BAD_F00D_DEAD_C0DEu64;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };

        for _ in 0..3000 {
            let len = (next() % 257) as usize;
            let msg: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            assert_eq!(
                whitebox_hmac_sha256(&msg),
                crypto::hmac_sha256(KEY, &msg),
                "white-box and standard HMAC must agree for len={len}"
            );
        }
    }

    /// Verify proofs produced by the white-box path with the production verifier
    /// (closes the device→server loop the parity criterion is about).
    #[test]
    fn whitebox_proof_verifies_with_standard_verifier() {
        let proof = whitebox_request_proof("tok-xyz", &crypto::sha256(b"POST /pay"), &[1, 2, 3, 4], 9);
        assert!(crypto::verify_request_proof(KEY, &proof));
        assert!(!crypto::verify_request_proof(b"wrong-key", &proof));
    }

    /// Table size is the figure cited in the design doc's perf budget.
    #[test]
    fn table_size_is_reported() {
        // 128 encoded bytes + 128 * 256-entry inverse tables.
        assert_eq!(table_size_bytes(), 128 + 128 * 256);
    }

    /// Informational perf + size print; behavior is asserted elsewhere.
    #[test]
    fn perf_and_size_report_prints_numbers() {
        println!("--- whitebox-spike measurement (informational; release numbers in doc) ---");
        let mut last = None;
        for &len in &[16usize, 55, 256] {
            let report = measure::run(200_000, len);
            println!(
                "msg_len={:>3}  std={:>7.1}ns  wb={:>7.1}ns  tax={:>5.2}x  tables={}B ({:.1}KB)",
                report.msg_len,
                report.std_ns,
                report.wb_ns,
                report.ratio,
                report.table_bytes,
                report.table_bytes as f64 / 1024.0,
            );
            last = Some(report);
        }
        let report = last.unwrap();
        assert!(report.table_bytes > 0);
    }
}
