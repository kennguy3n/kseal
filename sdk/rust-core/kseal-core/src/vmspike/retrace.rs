//! The crash-symbolication mitigation: a **private, encrypted de-virtualization
//! / retrace map** keyed off the build seed.
//!
//! Virtualization breaks ordinary symbolication — every virtualized method
//! crashes inside the VM dispatch loop, and `mapping.txt`/dSYM cannot express
//! "VM program → source". The mitigation (mirroring Guardsquare's "retrace") is
//! to emit, at build time, a map from VM program counter to the original source
//! site, ship it **out of band**, encrypted, and resolve crashes internally.
//!
//! Here that map is serialized and XOR-encrypted under a key derived from the
//! [`BuildSeed`]. A [`Symbolicator`] opens it with the same seed and resolves a
//! captured [`VmFrame`]; opening with the wrong seed fails the
//! magic/checksum/seed-tag check, so an attacker who lifts the artifact without
//! the key gets nothing.
//! Production would replace the XOR keystream with a real AEAD under a
//! KMS-managed key — see `docs/virtualization-tier-decision.md`.

use super::encode::{fnv1a64, keystream_byte, subkey, BuildSeed};
use super::interp::VmFrame;

/// Magic prefix identifying an encrypted retrace map.
const MAGIC: [u8; 4] = *b"KVRM";
/// Retrace-map format version.
const VERSION: u8 = 1;

/// A source site recorded at lowering time (cheap, `'static`).
///
/// `source_line` is the line of the *lowering* statement that emitted the
/// instruction. In the spike this stands in for a production DWARF line-table
/// entry pointing at the pre-virtualization source; the symbolication mechanism
/// is identical either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSite {
    /// Originating function name.
    pub function: &'static str,
    /// Human-readable description of the source step.
    pub step: &'static str,
    /// Source line associated with the step.
    pub source_line: u32,
}

/// A resolved source site (owned), returned by the [`Symbolicator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSite {
    /// Originating function name.
    pub function: String,
    /// Human-readable description of the source step.
    pub step: String,
    /// Source line associated with the step.
    pub source_line: u32,
}

/// Why opening or parsing a retrace map failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetraceError {
    /// Buffer ended before a field could be read.
    TooShort,
    /// Magic prefix did not match (typically a wrong seed).
    BadMagic,
    /// Unsupported version.
    BadVersion,
    /// Checksum mismatch (corruption or wrong seed).
    BadChecksum,
    /// The embedded build-seed tag did not match the supplied seed.
    SeedMismatch,
}

/// Serializes `entries` into a plaintext retrace map and encrypts it under the
/// key derived from `seed`. The build seed is also folded in as a bound tag so a
/// map cannot be silently paired with a different build's frames;
/// [`Symbolicator::open`] verifies it and rejects a mismatch with
/// [`RetraceError::SeedMismatch`].
#[must_use]
pub fn encrypt_map(entries: &[(u32, SourceSite)], seed: &BuildSeed) -> Vec<u8> {
    let seed_tag = subkey(seed, b"kseal/vmspike/retrace-tag");

    let mut raw: Vec<u8> = Vec::new();
    raw.extend_from_slice(&MAGIC);
    raw.push(VERSION);
    raw.extend_from_slice(&seed_tag.to_be_bytes());
    raw.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (pc, site) in entries {
        raw.extend_from_slice(&pc.to_be_bytes());
        raw.extend_from_slice(&site.source_line.to_be_bytes());
        put_str(&mut raw, site.function);
        put_str(&mut raw, site.step);
    }
    // FNV-1a is a non-cryptographic checksum (corruption/wrong-seed detection only,
    // not integrity/authenticity); production uses AEAD under a KMS key — see the
    // module doc and docs/virtualization-tier-decision.md §6.
    let checksum = fnv1a64(&raw);
    raw.extend_from_slice(&checksum.to_be_bytes());

    let key = subkey(seed, b"kseal/vmspike/retrace-key");
    for (i, b) in raw.iter_mut().enumerate() {
        *b ^= keystream_byte(key, i);
    }
    raw
}

/// Opens an encrypted retrace map and resolves captured VM frames.
#[derive(Debug, Clone)]
pub struct Symbolicator {
    entries: Vec<(u32, ResolvedSite)>,
}

impl Symbolicator {
    /// Decrypts and parses an encrypted retrace map under `seed`.
    ///
    /// # Errors
    /// Returns [`RetraceError`] if the buffer is truncated, if the
    /// magic/version/checksum do not validate, or if the embedded seed tag does
    /// not match `seed` — the expected outcome when the wrong seed (key) is
    /// supplied.
    pub fn open(encrypted: &[u8], seed: &BuildSeed) -> Result<Self, RetraceError> {
        let key = subkey(seed, b"kseal/vmspike/retrace-key");
        let mut raw = encrypted.to_vec();
        for (i, b) in raw.iter_mut().enumerate() {
            *b ^= keystream_byte(key, i);
        }
        if raw.len() < 8 {
            return Err(RetraceError::TooShort);
        }
        let split = raw.len() - 8;
        let want = fnv1a64(&raw[..split]);
        let got = u64::from_be_bytes(raw[split..].try_into().map_err(|_| RetraceError::TooShort)?);
        if want != got {
            return Err(RetraceError::BadChecksum);
        }

        let mut r = Reader::new(&raw[..split]);
        if r.take(4)? != MAGIC {
            return Err(RetraceError::BadMagic);
        }
        if r.u8()? != VERSION {
            return Err(RetraceError::BadVersion);
        }
        let seed_tag = r.u64()?;
        if seed_tag != subkey(seed, b"kseal/vmspike/retrace-tag") {
            return Err(RetraceError::SeedMismatch);
        }
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
    fn u8(&mut self) -> Result<u8, RetraceError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, RetraceError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, RetraceError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, RetraceError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    fn string(&mut self) -> Result<String, RetraceError> {
        let n = self.u16()? as usize;
        let b = self.take(n)?;
        Ok(String::from_utf8_lossy(b).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::isa::lower_tag_mix;

    #[test]
    fn resolves_a_known_pc_through_the_encrypted_map() {
        let lowered = lower_tag_mix();
        let seed = BuildSeed::from_u64(99);
        let enc = encrypt_map(&lowered.retrace, &seed);
        let sym = Symbolicator::open(&enc, &seed).unwrap();
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
        let enc = encrypt_map(&lowered.retrace, &BuildSeed::from_u64(1));
        assert!(Symbolicator::open(&enc, &BuildSeed::from_u64(2)).is_err());
    }
}
