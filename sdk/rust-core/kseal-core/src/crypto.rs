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

/// Domain-separation tag for the signed-config envelope preimage (ASCII, no
/// NUL). Distinct from [`PROOF_DOMAIN`] so a request proof can never be
/// mistaken for a config signature and vice versa.
const SIGNED_CONFIG_DOMAIN: &[u8] = b"kseal/v1/signed-config";

/// Appends a 4-byte big-endian length prefix followed by `field` bytes.
///
/// The length prefix is a `u32`, so `field` must be at most `u32::MAX` bytes;
/// a longer field would truncate the prefix and silently diverge from the
/// server's preimage. Every real field (22-byte domain, token id, 32-byte
/// hash, 16-byte nonce, key id, config bytes) is orders of magnitude under
/// that, so this is purely an explicit-contract guard, debug-asserted at zero
/// release cost.
fn push_lp(buf: &mut Vec<u8>, field: &[u8]) {
    debug_assert!(
        field.len() <= u32::MAX as usize,
        "length-prefixed field exceeds u32 prefix",
    );
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

/// Builds the canonical, domain-separated, length-prefixed signing preimage for
/// a [`crate::proto::SignedConfig`] envelope:
///
/// ```text
/// preimage =
///     u32_be(len(DOMAIN))        || DOMAIN
///   || i64_be(version)
///   || i64_be(ttl_seconds)
///   || u32_be(len(key_id_utf8))  || key_id_utf8
///   || u32_be(len(config_bytes)) || config_bytes
/// ```
///
/// `DOMAIN = "kseal/v1/signed-config"`. The two scalars are fixed-width 8-byte
/// big-endian `i64` (no length prefix); the variable-length `key_id` and
/// `config_bytes` are length-prefixed so the framing is unambiguous. The
/// Ed25519 signature is computed/verified over these exact bytes, which
/// authenticates the previously-unsigned envelope fields (`version`,
/// `ttl_seconds`, `key_id`) alongside `config_bytes`. The Go server (S1)
/// produces the identical layout when it signs; any divergence breaks
/// verification.
#[must_use]
pub fn signed_config_preimage(
    version: i64,
    ttl_seconds: i64,
    key_id: &str,
    config_bytes: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        core::mem::size_of::<u32>()
            + SIGNED_CONFIG_DOMAIN.len()
            + 2 * core::mem::size_of::<i64>()
            + 2 * core::mem::size_of::<u32>()
            + key_id.len()
            + config_bytes.len(),
    );
    push_lp(&mut msg, SIGNED_CONFIG_DOMAIN);
    msg.extend_from_slice(&version.to_be_bytes());
    msg.extend_from_slice(&ttl_seconds.to_be_bytes());
    push_lp(&mut msg, key_id.as_bytes());
    push_lp(&mut msg, config_bytes);
    msg
}

/// Verifies an Ed25519 `signature` over the canonical signed-config envelope
/// preimage (see [`signed_config_preimage`]) against `public_key`.
///
/// Unlike a bare signature over `config_bytes`, this authenticates the
/// security-relevant envelope fields (`version` — the rollback anchor — and
/// `ttl_seconds` — the staleness anchor), closing the CDN/cache tamper vector.
/// Returns `false` (never an error) on any malformed input or failed check.
#[must_use]
pub fn verify_config_envelope(
    public_key: &[u8],
    version: i64,
    ttl_seconds: i64,
    key_id: &str,
    config_bytes: &[u8],
    signature: &[u8],
) -> bool {
    let preimage = signed_config_preimage(version, ttl_seconds, key_id, config_bytes);
    verify_ed25519(public_key, &preimage, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Golden Ed25519 signature (hex) over the fixed signed-config vector in
    /// [`signed_config_preimage_exact_byte_layout`]. S1 must reproduce this.
    const GOLDEN_SIGNED_CONFIG_SIG_HEX: &str = "8fe81cf02eb57b7fdba657b35cfb5b9cbc33c0325e1dbca3c8f46765b837ab8645e02f7074f57bbfbb1c9c690b7a06803529ad6a43624f119c52015d71f40a09";

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

    #[test]
    fn signed_config_domain_is_exact() {
        assert_eq!(SIGNED_CONFIG_DOMAIN, b"kseal/v1/signed-config");
        assert_eq!(SIGNED_CONFIG_DOMAIN.len(), 22);
    }

    #[test]
    fn config_envelope_verifies_and_detects_tamper() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let config_bytes = b"serialized-policy-config";
        let (version, ttl, key_id) = (7i64, 3600i64, "k1");

        let sig = sk
            .sign(&signed_config_preimage(version, ttl, key_id, config_bytes))
            .to_bytes()
            .to_vec();
        assert!(verify_config_envelope(
            vk.as_bytes(),
            version,
            ttl,
            key_id,
            config_bytes,
            &sig
        ));

        // Tampering ANY authenticated envelope field now fails verification —
        // this is the whole point of envelope signing (vs signing only bytes).
        assert!(
            !verify_config_envelope(vk.as_bytes(), version + 1, ttl, key_id, config_bytes, &sig),
            "inflated version must fail"
        );
        assert!(
            !verify_config_envelope(vk.as_bytes(), version, ttl + 1, key_id, config_bytes, &sig),
            "inflated ttl must fail"
        );
        assert!(
            !verify_config_envelope(vk.as_bytes(), version, ttl, "k2", config_bytes, &sig),
            "swapped key_id must fail"
        );
        assert!(
            !verify_config_envelope(vk.as_bytes(), version, ttl, key_id, b"other", &sig),
            "tampered config_bytes must fail"
        );
    }

    /// Golden cross-platform vector for the signed-config envelope. The Go
    /// server (S1) MUST produce the identical preimage bytes and (since Ed25519
    /// is deterministic, RFC 8032) the identical signature for this fixed input.
    /// Layout: `u32_be(len)||DOMAIN || i64_be(version) || i64_be(ttl) ||
    /// u32_be(len)||key_id || u32_be(len)||config_bytes`.
    #[test]
    fn signed_config_preimage_exact_byte_layout() {
        let version: i64 = 7;
        let ttl_seconds: i64 = 3600; // 0x0E10
        let key_id = "k1"; // 2 bytes: 6b 31
        let config_bytes = [0x01u8, 0x02, 0x03]; // 3 bytes

        let mut expected = Vec::new();
        // u32_be(22) || "kseal/v1/signed-config"
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x16]);
        expected.extend_from_slice(b"kseal/v1/signed-config");
        // i64_be(7)
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07]);
        // i64_be(3600)
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x10]);
        // u32_be(2) || "k1"
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        expected.extend_from_slice(&[0x6b, 0x31]);
        // u32_be(3) || 01 02 03
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]);
        expected.extend_from_slice(&[0x01, 0x02, 0x03]);

        let actual = signed_config_preimage(version, ttl_seconds, key_id, &config_bytes);
        assert_eq!(actual, expected, "preimage byte layout must match the spec");
        // Total = 4 + 22 + 8 + 8 + 4 + 2 + 4 + 3.
        assert_eq!(actual.len(), 4 + 22 + 8 + 8 + 4 + 2 + 4 + 3);

        // Golden Ed25519 signature over this preimage with signing key [7u8;32],
        // for S1 to match byte-for-byte.
        let sk = fixed_signing_key();
        let sig = sk.sign(&actual).to_bytes();
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            sig_hex, GOLDEN_SIGNED_CONFIG_SIG_HEX,
            "golden Ed25519 signature for the fixed vector"
        );
        // And it verifies against the matching public key.
        assert!(verify_config_envelope(
            sk.verifying_key().as_bytes(),
            version,
            ttl_seconds,
            key_id,
            &config_bytes,
            &sig
        ));
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
