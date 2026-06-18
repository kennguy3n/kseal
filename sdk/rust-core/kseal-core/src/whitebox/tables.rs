//! Compile-time-generated **encoded key tables** for the white-box spike.
//!
//! The two HMAC key blocks — `k_ipad = K' ^ ipad` and `k_opad = K' ^ opad`
//! (where `K'` is the proof key zero-padded to the SHA-256 block size) — are the
//! only secret-bearing inputs to `HMAC-SHA256`. Instead of shipping those bytes
//! verbatim, this module bakes them into per-byte **encoded lookup tables** at
//! compile time:
//!
//! * For each of the 128 key-block byte positions we generate a random byte
//!   bijection `S_i` (a 256-entry permutation of `0..=255`) from a deterministic
//!   compile-time PRNG.
//! * We store the *encoded* byte `enc_i = S_i(b_i)` and the *inverse* table
//!   `S_i^{-1}`. The plaintext byte `b_i` is recovered at runtime as
//!   `b_i = S_i^{-1}[enc_i]`.
//!
//! The whole derivation runs inside `const fn`s, so the raw proof key
//! ([`SPIKE_PROOF_KEY`]) is *consumed during const-evaluation* and never emitted
//! as a runtime symbol. A static dump of the shipped artifact contains only the
//! encoded byte vector and the permutation tables — never the contiguous key.
//! See the module banner in [`super`] for the (honest) threat-model caveats.

/// SHA-256 block size in bytes (HMAC key-block width).
pub(crate) const BLOCK: usize = 64;

/// Number of encoded key-block positions: `k_ipad` (64) followed by `k_opad`
/// (64).
const POSITIONS: usize = 2 * BLOCK;

/// The spike's proof key, expressed as raw byte values (the ASCII of
/// `"kseal-test-instance-key"`) rather than a string literal so no readable
/// string is ever placed in `.rodata`. It is referenced *only* inside the
/// `const fn` table generator below, so const-evaluation consumes it and it is
/// not present in the compiled binary.
///
/// This is the project's golden proof-HMAC key (see the `proof_preimage`
/// golden vector in `crypto.rs`), pinned here so the spike can prove byte-for-
/// byte parity against the shipped golden tag. Productionizing would generate
/// per-tenant tables in the build plane from a key that never appears in source.
const SPIKE_PROOF_KEY: [u8; 23] = [
    0x6b, 0x73, 0x65, 0x61, 0x6c, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x69, 0x6e, 0x73, 0x74, 0x61,
    0x6e, 0x63, 0x65, 0x2d, 0x6b, 0x65, 0x79,
];

/// HMAC inner-pad byte (`ipad`).
const IPAD: u8 = 0x36;
/// HMAC outer-pad byte (`opad`).
const OPAD: u8 = 0x5c;

/// Master seed for the per-position permutation PRNG. Changing this re-rolls
/// every encoding table (the spike analogue of per-build table polymorphism).
const MASTER_SEED: u64 = 0xA5A5_1234_DEAD_BEEF;

/// The baked white-box tables: encoded key-block bytes plus the per-position
/// inverse permutations used to decode them.
struct WbTables {
    /// `enc[i] = S_i(key_block_byte(i))` — the encoded key material.
    enc: [u8; POSITIONS],
    /// `sinv[i] = S_i^{-1}` — the 256-entry inverse permutation for position `i`.
    sinv: [[u8; 256]; POSITIONS],
}

/// One SplitMix64 step: returns `(next_state, output)`.
const fn sm_step(state: u64) -> (u64, u64) {
    let ns = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = ns;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (ns, z ^ (z >> 31))
}

/// Derives an independent permutation seed for byte position `i`.
const fn pos_seed(i: usize) -> u64 {
    let (_, r) = sm_step(MASTER_SEED ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    r
}

/// Builds a random byte bijection and its inverse via const-time Fisher-Yates.
const fn gen_perm(seed: u64) -> ([u8; 256], [u8; 256]) {
    let mut p = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        p[i] = i as u8;
        i += 1;
    }
    let mut state = seed;
    let mut j = 255usize;
    while j >= 1 {
        let (ns, r) = sm_step(state);
        state = ns;
        let k = (r % (j as u64 + 1)) as usize;
        let tmp = p[j];
        p[j] = p[k];
        p[k] = tmp;
        j -= 1;
    }
    let mut inv = [0u8; 256];
    let mut t = 0;
    while t < 256 {
        inv[p[t] as usize] = t as u8;
        t += 1;
    }
    (p, inv)
}

/// Returns the plaintext key-block byte at position `i`:
/// positions `0..BLOCK` are `k_ipad`, `BLOCK..2*BLOCK` are `k_opad`.
const fn key_block_byte(i: usize) -> u8 {
    let pos = i % BLOCK;
    let kb = if pos < SPIKE_PROOF_KEY.len() {
        SPIKE_PROOF_KEY[pos]
    } else {
        0u8
    };
    let pad = if i < BLOCK { IPAD } else { OPAD };
    kb ^ pad
}

/// Generates the encoded tables at compile time. Each position's permutation is
/// computed once and used both to encode the key byte and to store its inverse,
/// so the raw key block is never materialized as stored data.
const fn build_tables() -> WbTables {
    let mut enc = [0u8; POSITIONS];
    let mut sinv = [[0u8; 256]; POSITIONS];
    let mut i = 0;
    while i < POSITIONS {
        let (fwd, inv) = gen_perm(pos_seed(i));
        enc[i] = fwd[key_block_byte(i) as usize];
        sinv[i] = inv;
        i += 1;
    }
    WbTables { enc, sinv }
}

/// The shipped, compile-time-baked white-box tables.
static TABLES: WbTables = build_tables();

/// Total size in bytes of the baked white-box tables (encoded bytes + inverse
/// permutation tables). Reported by the spike's perf/size accounting.
pub const WHITEBOX_TABLE_BYTES: usize = core::mem::size_of::<WbTables>();

/// Decodes the two HMAC key blocks (`k_ipad`, `k_opad`) from the encoded tables.
///
/// This is the only point at which the plaintext key blocks exist, and only
/// transiently on the stack; callers scrub them after use.
pub(crate) fn key_ipad_opad() -> ([u8; BLOCK], [u8; BLOCK]) {
    let mut k_ipad = [0u8; BLOCK];
    let mut k_opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        k_ipad[i] = TABLES.sinv[i][TABLES.enc[i] as usize];
        k_opad[i] = TABLES.sinv[BLOCK + i][TABLES.enc[BLOCK + i] as usize];
    }
    (k_ipad, k_opad)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The baked table data must not contain the contiguous raw key — the
    /// central static-extraction claim of the spike, checked over the actual
    /// shipped bytes.
    #[test]
    fn encoded_tables_do_not_contain_raw_key() {
        let mut blob = Vec::with_capacity(WHITEBOX_TABLE_BYTES);
        blob.extend_from_slice(&TABLES.enc);
        for row in &TABLES.sinv {
            blob.extend_from_slice(row);
        }

        let key = SPIKE_PROOF_KEY;
        let appears = blob.windows(key.len()).any(|w| w == key);
        assert!(!appears, "raw proof key must not appear in the baked tables");

        // The reconstructed key blocks must likewise be absent verbatim.
        let (k_ipad, k_opad) = key_ipad_opad();
        for block in [&k_ipad[..], &k_opad[..]] {
            let present = blob.windows(block.len()).any(|w| w == block);
            assert!(!present, "raw key block must not appear in the baked tables");
        }
    }

    /// Decoding must invert the encoding exactly for every position.
    #[test]
    fn decode_round_trips_every_position() {
        let (k_ipad, k_opad) = key_ipad_opad();
        for i in 0..BLOCK {
            assert_eq!(k_ipad[i], key_block_byte(i));
            assert_eq!(k_opad[i], key_block_byte(BLOCK + i));
        }
    }
}
