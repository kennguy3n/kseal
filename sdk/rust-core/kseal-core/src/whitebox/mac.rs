//! The white-box keyed MAC: reconstructs the HMAC key blocks from the encoded
//! tables and reproduces `HMAC-SHA256` exactly via the vetted `sha2` crate.
//!
//! For a key no longer than the block size,
//! `HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))`. The spike key is 23
//! bytes, so `K'` is the key zero-padded to 64 bytes and the two key blocks are
//! exactly the per-block inputs `sha2` would derive internally. Feeding the
//! decoded blocks in directly therefore yields a byte-for-byte-identical tag to
//! [`crate::crypto::hmac_sha256`] — without ever storing the raw key.

use super::tables;
use sha2::{Digest, Sha256};

/// Computes the white-box `HMAC-SHA256` tag over `message` using the baked
/// proof-key tables. The result is identical to
/// `crypto::hmac_sha256(proof_key, message)`.
///
/// The plaintext key blocks are reconstructed on the stack, used immediately,
/// and best-effort scrubbed (with a [`core::hint::black_box`] fence so the
/// writes are not elided) before returning, to shrink the in-memory window in
/// which they exist.
#[must_use]
pub fn whitebox_hmac_sha256(message: &[u8]) -> [u8; 32] {
    let (mut k_ipad, mut k_opad) = tables::key_ipad_opad();

    let mut inner = Sha256::new();
    inner.update(k_ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(k_opad);
    outer.update(inner_digest);
    let digest = outer.finalize();

    k_ipad.fill(0);
    k_opad.fill(0);
    core::hint::black_box(&k_ipad);
    core::hint::black_box(&k_opad);

    let mut tag = [0u8; 32];
    tag.copy_from_slice(&digest);
    tag
}
