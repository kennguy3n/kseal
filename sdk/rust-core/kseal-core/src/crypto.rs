//! Cryptographic primitives used by the trust core.
//!
//! All primitives delegate to vetted crates — `ed25519-dalek` for signatures,
//! `hmac` + `sha2` for request proofs, and `getrandom` for nonces. Nothing is
//! hand-rolled. The request-proof construction is the cross-platform contract,
//! using domain separation and length-prefixed framing so the preimage is
//! canonical (no field-boundary ambiguity from the variable-length `token_id`
//! or `nonce`):
//!
//! ```text
//! DOMAIN = "kseal/v1/request-proof"   // ASCII, no NUL terminator
//!
//! preimage =
//!     u32_be(len(DOMAIN))         || DOMAIN
//!   || u32_be(len(token_id_utf8)) || token_id_utf8
//!   || u32_be(len(request_hash))  || request_hash
//!   || u32_be(len(nonce))         || nonce
//!   || i64_be(monotonic_sequence)            // fixed 8 bytes, no length prefix
//!
//! tag = HMAC-SHA256(instance_key, preimage)
//! ```
//!
//! Every length prefix is a 4-byte big-endian `u32`; the trailing sequence is a
//! fixed-width 8-byte big-endian `i64`. The Go server (S1) recomputes this exact
//! byte layout to verify, so any deviation breaks verification.

use crate::proto::RequestProof;
use crate::{Error, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Length in bytes of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Length in bytes of an HMAC-SHA256 tag.
pub const HMAC_SHA256_LEN: usize = 32;
/// Default nonce length (128 bits) used for challenges and request proofs.
pub const DEFAULT_NONCE_LEN: usize = 16;

/// Verifies an Ed25519 `signature` over `message` against `public_key`.
///
/// Returns `false` (never an error) for malformed keys/signatures or a failed
/// check, so callers get a single boolean trust decision. Uses `verify_strict`
/// to reject non-canonical / small-order public keys.
#[must_use]
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk_bytes) = <[u8; ED25519_PUBLIC_KEY_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; ED25519_SIGNATURE_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(message, &sig).is_ok()
}

/// Computes `HMAC-SHA256(key, message)`.
///
/// The key may be any length (HMAC handles padding/hashing internally).
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_SHA256_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// SHA-256 digest of `data`; handy for canonicalizing a request into a hash.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Fills `len` bytes of cryptographically secure randomness for use as a nonce.
///
/// # Errors
/// Returns [`Error::Crypto`] if the OS RNG is unavailable.
pub fn generate_nonce(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|e| Error::Crypto(format!("rng failure: {e}")))?;
    Ok(buf)
}

/// Domain-separation tag for the request-proof preimage (ASCII, no NUL).
const PROOF_DOMAIN: &[u8] = b"kseal/v1/request-proof";

/// Appends a 4-byte big-endian length prefix followed by `field` bytes.
fn push_lp(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Builds the canonical, domain-separated, length-prefixed proof preimage:
///
/// `u32_be(len(DOMAIN)) || DOMAIN || u32_be(len(token_id)) || token_id ||
///  u32_be(len(request_hash)) || request_hash || u32_be(len(nonce)) || nonce ||
///  i64_be(seq)`
///
/// The trailing sequence is a fixed-width 8-byte big-endian `i64` with no length
/// prefix. See the [module docs](self) — the server mirrors this exactly.
fn proof_preimage(token_id: &str, request_hash: &[u8], nonce: &[u8], seq: i64) -> Vec<u8> {
    // 4 length-prefixed fields (4 bytes each) + their payloads + 8-byte seq.
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

/// Generates a [`RequestProof`] binding a request to a trust token.
///
/// The `app_instance_signature` field carries the HMAC-SHA256 tag computed over
/// the canonical preimage with the instance's hardware-bound key.
#[must_use]
pub fn generate_request_proof(
    key: &[u8],
    token_id: &str,
    request_hash: &[u8],
    nonce: &[u8],
    seq: i64,
) -> RequestProof {
    let tag = hmac_sha256(key, &proof_preimage(token_id, request_hash, nonce, seq));
    RequestProof {
        trust_token_id: token_id.to_string(),
        request_hash: request_hash.to_vec(),
        nonce: nonce.to_vec(),
        app_instance_signature: tag.to_vec(),
        monotonic_sequence: seq,
    }
}

/// Verifies a [`RequestProof`] against the instance `key` in constant time.
///
/// This mirrors the server-side check (kseal also verifies proofs at the edge),
/// and is used by FFI round-trip tests. Comparison is constant-time via the
/// `hmac` crate's `verify_slice`.
#[must_use]
pub fn verify_request_proof(key: &[u8], proof: &RequestProof) -> bool {
    let msg = proof_preimage(
        &proof.trust_token_id,
        &proof.request_hash,
        &proof.nonce,
        proof.monotonic_sequence,
    );
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(&msg);
    mac.verify_slice(&proof.app_instance_signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn ed25519_round_trip() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let msg = b"signed config bytes";
        let sig = sk.sign(msg);
        assert!(verify_ed25519(vk.as_bytes(), msg, &sig.to_bytes()));
    }

    #[test]
    fn ed25519_rejects_tampered_message() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert!(!verify_ed25519(vk.as_bytes(), b"tampered", &sig.to_bytes()));
    }

    #[test]
    fn ed25519_rejects_malformed_inputs() {
        assert!(!verify_ed25519(
            &[0u8; 10],
            b"m",
            &[0u8; ED25519_SIGNATURE_LEN]
        ));
        assert!(!verify_ed25519(
            &[0u8; ED25519_PUBLIC_KEY_LEN],
            b"m",
            &[0u8; 10]
        ));
    }

    #[test]
    fn hmac_is_deterministic_and_keyed() {
        let a = hmac_sha256(b"key1", b"data");
        let b = hmac_sha256(b"key1", b"data");
        let c = hmac_sha256(b"key2", b"data");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), HMAC_SHA256_LEN);
    }

    #[test]
    fn nonce_has_requested_len_and_varies() {
        let n1 = generate_nonce(DEFAULT_NONCE_LEN).unwrap();
        let n2 = generate_nonce(DEFAULT_NONCE_LEN).unwrap();
        assert_eq!(n1.len(), DEFAULT_NONCE_LEN);
        assert_ne!(n1, n2, "two random nonces must differ");
    }

    #[test]
    fn request_proof_verifies_and_detects_replay() {
        let key = b"hw-bound-instance-key";
        let rh = sha256(b"POST /pay {amount:100}");
        let nonce = generate_nonce(DEFAULT_NONCE_LEN).unwrap();
        let proof = generate_request_proof(key, "tok-1", &rh, &nonce, 1);
        assert!(verify_request_proof(key, &proof));

        // A different sequence number yields a different signature.
        let mut replay = proof.clone();
        replay.monotonic_sequence = 2;
        assert!(!verify_request_proof(key, &replay));

        // A different key fails.
        assert!(!verify_request_proof(b"other-key", &proof));
    }

    #[test]
    fn proof_domain_is_exact() {
        assert_eq!(PROOF_DOMAIN, b"kseal/v1/request-proof");
        assert_eq!(PROOF_DOMAIN.len(), 22);
    }

    /// Golden cross-platform vector: the exact preimage byte layout for a fixed
    /// input. The Go server (S1) MUST produce the identical bytes. Layout:
    /// `u32_be(len)||DOMAIN || u32_be(len)||token_id || u32_be(len)||request_hash
    ///  || u32_be(len)||nonce || i64_be(seq)`.
    #[test]
    fn proof_preimage_exact_byte_layout() {
        // Fixed, easily-reproduced inputs.
        let token_id = "tok"; // 3 bytes: 74 6f 6b
        let request_hash = [0x01u8, 0x02, 0x03, 0x04]; // 4 bytes
        let nonce = [0xAAu8, 0xBB]; // 2 bytes
        let seq: i64 = 1;

        let mut expected = Vec::new();
        // u32_be(22) || "kseal/v1/request-proof"
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x16]);
        expected.extend_from_slice(b"kseal/v1/request-proof");
        // u32_be(3) || "tok"
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]);
        expected.extend_from_slice(&[0x74, 0x6f, 0x6b]);
        // u32_be(4) || 01 02 03 04
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        // u32_be(2) || AA BB
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        expected.extend_from_slice(&[0xAA, 0xBB]);
        // i64_be(1)
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

        let actual = proof_preimage(token_id, &request_hash, &nonce, seq);
        assert_eq!(actual, expected, "preimage byte layout must match the spec");

        // Total length = 4*(4 len prefixes) + 22 + 3 + 4 + 2 + 8.
        assert_eq!(actual.len(), 16 + 22 + 3 + 4 + 2 + 8);

        // Golden HMAC tag over this preimage with a fixed key, for S1 to match.
        let key = b"kseal-test-instance-key";
        let tag = hmac_sha256(key, &actual);
        let tag_hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            tag_hex, "718bb06df45dc4bbc5bf483bd65acf7609429966adba8baff66fa965857ebd0d",
            "golden HMAC tag for the fixed vector"
        );
    }
}
