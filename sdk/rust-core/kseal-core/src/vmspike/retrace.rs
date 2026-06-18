//! The crash-symbolication mitigation: a **private, encrypted and authenticated
//! de-virtualization / retrace map**, keyed off the build seed and bound to the
//! build's `build_hash`.
//!
//! Virtualization breaks ordinary symbolication — every virtualized method
//! crashes inside the VM dispatch loop, and `mapping.txt`/dSYM cannot express
//! "VM program → source". The mitigation (mirroring Guardsquare's "retrace") is
//! to emit, at build time, a map from VM program counter to the original source
//! site, ship it **out of band**, encrypted, and resolve crashes internally.
//!
//! Confidentiality and integrity are both real here:
//!
//! * **Encryption** — the entry table is XORed with a SHA-256 counter-mode
//!   keystream derived from the [`BuildSeed`] (and `build_hash`). Without the
//!   seed the entries are indistinguishable from random.
//! * **Authentication** — the whole artifact is covered by an HMAC-SHA256 tag
//!   (encrypt-then-MAC) under a separate seed-derived key, verified in constant
//!   time via the vetted `hmac` crate. Tampering or a wrong seed fails the tag.
//! * **Build binding** — the `build_hash` is carried in the authenticated header
//!   and folded into key derivation, so a map can only be opened against the
//!   build it was emitted for; pairing it with another build's frames is
//!   rejected.
//!
//! This is the spike's XOR-checksum scheme upgraded to a proper AEAD-shaped
//! construction. Production would swap the in-process key for a KMS/HSM-managed
//! key and ship the map through the crash pipeline — see
//! `docs/virtualization-tier-decision.md` §6 for key custody.

use super::encode::BuildSeed;
use super::interp::VmFrame;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Magic prefix identifying an encrypted retrace map.
const MAGIC: [u8; 4] = *b"KVRM";
/// Retrace-map format version (bumped: v1 was XOR + FNV checksum).
const VERSION: u8 = 2;
/// Length of the authenticated cleartext header: `MAGIC ‖ VERSION ‖ build_hash`.
const HEADER_LEN: usize = 4 + 1 + 32;
/// Length of the trailing HMAC-SHA256 tag.
const TAG_LEN: usize = 32;

/// A source site recorded at lowering time (cheap, `'static`).
///
/// `source_line` is the line of the *lowering* statement that emitted the
/// instruction (for the hand-lowered routine) or the IR node id (for
/// [`super::ir`]-compiled routines). In the spike this stands in for a
/// production DWARF line-table entry pointing at the pre-virtualization source;
/// the symbolication mechanism is identical either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSite {
    /// Originating function name.
    pub function: &'static str,
    /// Human-readable description of the source step.
    pub step: &'static str,
    /// Source line (or IR node id) associated with the step.
    pub source_line: u32,
}

/// A resolved source site (owned), returned by the [`Symbolicator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSite {
    /// Originating function name.
    pub function: String,
    /// Human-readable description of the source step.
    pub step: String,
    /// Source line (or IR node id) associated with the step.
    pub source_line: u32,
}

/// Why opening or parsing a retrace map failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetraceError {
    /// Buffer ended before a field could be read.
    TooShort,
    /// Magic prefix did not match.
    BadMagic,
    /// Unsupported version.
    BadVersion,
    /// The authenticated `build_hash` did not match the one supplied to
    /// [`Symbolicator::open`].
    BuildHashMismatch,
    /// HMAC verification failed — corruption, tampering, or (most often) a wrong
    /// build seed. This is the "useless without the key" outcome.
    AuthFailed,
}

/// Derives a 32-byte sub-key for `label`, bound to both `seed` and `build_hash`.
fn derive_key(seed: &BuildSeed, build_hash: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(seed.0);
    h.update(build_hash);
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    k
}

/// SHA-256 counter-mode keystream of `len` bytes under `key`.
///
/// Block `n` is `SHA-256("…ctr" ‖ key ‖ n_be64)`; concatenated and truncated.
/// This is a PRF-based stream cipher — strong enough that the map is opaque
/// without the seed — standing in for the KMS-backed AEAD production will use.
fn keystream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"kseal/vmspike/retrace-ctr");
        h.update(key);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Serializes `entries` into a retrace map, encrypts the entry table under a
/// `seed`+`build_hash`-derived keystream, and appends an HMAC-SHA256 tag over
/// the authenticated header and ciphertext.
///
/// The `build_hash` is carried in the clear (it is a public build identifier)
/// but authenticated, so the artifact is cryptographically bound to one build.
#[must_use]
pub fn encrypt_map(entries: &[(u32, SourceSite)], seed: &BuildSeed, build_hash: &[u8; 32]) -> Vec<u8> {
    // Plaintext entry table.
    let mut pt: Vec<u8> = Vec::new();
    pt.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (pc, site) in entries {
        pt.extend_from_slice(&pc.to_be_bytes());
        pt.extend_from_slice(&site.source_line.to_be_bytes());
        put_str(&mut pt, site.function);
        put_str(&mut pt, site.step);
    }

    // Encrypt the entry table (the confidential part).
    let enc_key = derive_key(seed, build_hash, b"kseal/vmspike/retrace-enc");
    let ks = keystream(&enc_key, pt.len());
    for (b, k) in pt.iter_mut().zip(&ks) {
        *b ^= *k;
    }

    // Assemble authenticated header ‖ ciphertext, then append the MAC tag.
    let mut out = Vec::with_capacity(HEADER_LEN + pt.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(build_hash);
    out.extend_from_slice(&pt);

    let mac_key = derive_key(seed, build_hash, b"kseal/vmspike/retrace-mac");
    let tag = mac(&mac_key, &out);
    out.extend_from_slice(&tag);
    out
}

/// Computes HMAC-SHA256 of `msg` under `key` using the vetted `hmac` crate.
fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Opens an encrypted retrace map and resolves captured VM frames.
#[derive(Debug, Clone)]
pub struct Symbolicator {
    entries: Vec<(u32, ResolvedSite)>,
}

impl Symbolicator {
    /// Verifies and decrypts an encrypted retrace map under `seed`, requiring it
    /// to be bound to `build_hash`.
    ///
    /// # Errors
    /// Returns [`RetraceError`] if the buffer is truncated, the magic/version is
    /// wrong, the `build_hash` does not match, or the HMAC tag does not verify —
    /// the last being the expected outcome for a wrong seed (no key) or any
    /// tampering.
    pub fn open(
        encrypted: &[u8],
        seed: &BuildSeed,
        build_hash: &[u8; 32],
    ) -> Result<Self, RetraceError> {
        if encrypted.len() < HEADER_LEN + TAG_LEN {
            return Err(RetraceError::TooShort);
        }
        let (body, tag) = encrypted.split_at(encrypted.len() - TAG_LEN);

        if body[..4] != MAGIC {
            return Err(RetraceError::BadMagic);
        }
        if body[4] != VERSION {
            return Err(RetraceError::BadVersion);
        }
        if &body[5..HEADER_LEN] != build_hash {
            return Err(RetraceError::BuildHashMismatch);
        }

        // Authenticate before touching the ciphertext (constant-time verify).
        let mac_key = derive_key(seed, build_hash, b"kseal/vmspike/retrace-mac");
        let mut m = HmacSha256::new_from_slice(&mac_key).expect("HMAC accepts keys of any length");
        m.update(body);
        if m.verify_slice(tag).is_err() {
            return Err(RetraceError::AuthFailed);
        }

        // Decrypt the entry table.
        let enc_key = derive_key(seed, build_hash, b"kseal/vmspike/retrace-enc");
        let mut pt = body[HEADER_LEN..].to_vec();
        let ks = keystream(&enc_key, pt.len());
        for (b, k) in pt.iter_mut().zip(&ks) {
            *b ^= *k;
        }

        let mut r = Reader::new(&pt);
        let count = r.u32()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let pc = r.u32()?;
            let source_line = r.u32()?;
            let function = r.string()?;
            let step = r.string()?;
            entries.push((
                pc,
                ResolvedSite {
                    function,
                    step,
                    source_line,
                },
            ));
        }
        Ok(Symbolicator { entries })
    }

    /// Resolves a captured [`VmFrame`] to its source site, if the pc is mapped.
    #[must_use]
    pub fn resolve(&self, frame: VmFrame) -> Option<ResolvedSite> {
        self.entries
            .iter()
            .find(|(pc, _)| *pc == frame.pc)
            .map(|(_, site)| site.clone())
    }

    /// Number of mapped program counters.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Derives a stable, public `build_hash` from a [`BuildSeed`] for the demo /
/// tests. Production supplies the real build identifier (e.g. the existing
/// per-build HKDF output) instead.
#[must_use]
pub fn build_hash_from_seed(seed: &BuildSeed) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"kseal/vmspike/demo-build-hash");
    h.update(seed.0);
    let d = h.finalize();
    let mut bh = [0u8; 32];
    bh.copy_from_slice(&d);
    bh
}

fn put_str(raw: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    raw.extend_from_slice(&(b.len() as u16).to_be_bytes());
    raw.extend_from_slice(b);
}

/// Minimal bounds-checked big-endian reader for the retrace map.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], RetraceError> {
        let end = self.pos.checked_add(n).ok_or(RetraceError::TooShort)?;
        let slice = self.buf.get(self.pos..end).ok_or(RetraceError::TooShort)?;
        self.pos = end;
        Ok(slice)
    }
    fn u16(&mut self) -> Result<u16, RetraceError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, RetraceError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Result<String, RetraceError> {
        let n = self.u16()? as usize;
        let b = self.take(n)?;
        Ok(String::from_utf8_lossy(b).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::super::isa::lower_tag_mix;
    use super::*;

    #[test]
    fn resolves_a_known_pc_through_the_encrypted_map() {
        let lowered = lower_tag_mix();
        let seed = BuildSeed::from_u64(99);
        let bh = build_hash_from_seed(&seed);
        let enc = encrypt_map(&lowered.retrace, &seed, &bh);
        let sym = Symbolicator::open(&enc, &seed, &bh).unwrap();
        assert_eq!(sym.entry_count(), lowered.retrace.len());

        // Pick the multiply step and confirm it resolves to native_tag_mix.
        let (pc, site) = lowered
            .retrace
            .iter()
            .find(|(_, s)| s.step.contains("MIX_PRIME)"))
            .copied()
            .unwrap();
        let resolved = sym.resolve(VmFrame { pc }).unwrap();
        assert_eq!(resolved.function, "native_tag_mix");
        assert_eq!(resolved.step, site.step);
        assert_eq!(resolved.source_line, site.source_line);
    }

    #[test]
    fn wrong_seed_cannot_open_the_map() {
        let lowered = lower_tag_mix();
        let seed = BuildSeed::from_u64(1);
        let bh = build_hash_from_seed(&seed);
        let enc = encrypt_map(&lowered.retrace, &seed, &bh);
        // Wrong seed: build_hash still matches (it is public), so the failure is
        // the HMAC tag — i.e. the map is useless without the key.
        assert_eq!(
            Symbolicator::open(&enc, &BuildSeed::from_u64(2), &bh).err(),
            Some(RetraceError::AuthFailed)
        );
    }

    #[test]
    fn tampering_any_byte_is_detected() {
        let lowered = lower_tag_mix();
        let seed = BuildSeed::from_u64(0x1234);
        let bh = build_hash_from_seed(&seed);
        let enc = encrypt_map(&lowered.retrace, &seed, &bh);

        // Flip one bit in the ciphertext region and one in the tag region.
        for idx in [HEADER_LEN + 1, enc.len() - 1] {
            let mut bad = enc.clone();
            bad[idx] ^= 0x01;
            assert_eq!(
                Symbolicator::open(&bad, &seed, &bh).err(),
                Some(RetraceError::AuthFailed),
                "tamper at {idx} must fail auth"
            );
        }
    }

    #[test]
    fn map_is_bound_to_its_build_hash() {
        let lowered = lower_tag_mix();
        let seed = BuildSeed::from_u64(0x5151);
        let bh = build_hash_from_seed(&seed);
        let enc = encrypt_map(&lowered.retrace, &seed, &bh);

        let other_bh = build_hash_from_seed(&BuildSeed::from_u64(0x6262));
        assert_eq!(
            Symbolicator::open(&enc, &seed, &other_bh).err(),
            Some(RetraceError::BuildHashMismatch)
        );
    }

    #[test]
    fn entries_are_encrypted_not_plaintext() {
        // The function-name strings must not appear in the clear in the artifact.
        let lowered = lower_tag_mix();
        let seed = BuildSeed::from_u64(0x9090);
        let bh = build_hash_from_seed(&seed);
        let enc = encrypt_map(&lowered.retrace, &seed, &bh);
        let needle = b"native_tag_mix";
        let found = enc.windows(needle.len()).any(|w| w == needle);
        assert!(!found, "source identifiers must be encrypted");
    }
}
