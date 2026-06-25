//! Per-build **polymorphic** byte encoding of a [`Program`].
//!
//! A real virtualization tier ships a *different* virtual instruction set per
//! build, so a devirtualizer crafted for one build does not generalize to the
//! next. This module demonstrates that property deterministically: from an
//! explicit 32-byte [`BuildSeed`] it derives
//!
//! * an **opcode permutation** — the wire byte for each opcode tag,
//! * a **register permutation** — the wire byte for each register index, and
//! * a **keystream** XORed over the whole encoded stream.
//!
//! Two different seeds therefore yield completely different bytecode for the
//! same source [`Program`], while a *fixed* seed is fully deterministic — which
//! is what keeps the shipped `build_hash` reproducible. A small magic header and
//! a trailing checksum mean decoding with the wrong seed fails cleanly
//! ([`DecodeError`]) instead of silently producing a different program.
//!
//! The seed derivation reuses the crate's existing `sha2` dependency (no new
//! third-party code); the keystream is an in-repo SplitMix64, mirroring
//! [`crate::obfuscate`]. This is a spike: production would key the stream from a
//! real KDF/KMS rather than a shipped seed.

use sha2::{Digest, Sha256};

use super::isa::{Instr, Program, NUM_OPS, NUM_REGS};

/// Magic prefix identifying an encoded vmspike program.
const MAGIC: [u8; 4] = *b"KVMS";
/// Encoding format version.
const VERSION: u8 = 1;

/// The explicit per-build polymorphism seed. In production this would be the
/// existing per-build HKDF output / `build_hash`; here it is supplied directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildSeed(pub [u8; 32]);

impl BuildSeed {
    /// Convenience constructor from a `u64` (broadcast into the 32-byte seed via
    /// SHA-256) for tests and harnesses.
    #[must_use]
    pub fn from_u64(x: u64) -> Self {
        let mut h = Sha256::new();
        h.update(b"kseal/vmspike/seed-from-u64");
        h.update(x.to_be_bytes());
        let d = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&d);
        BuildSeed(s)
    }
}

/// Why decoding failed (almost always: decoding with the wrong build seed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer ended before a field could be read.
    TooShort,
    /// Magic prefix did not match (typically a wrong seed).
    BadMagic,
    /// Unsupported format version.
    BadVersion,
    /// Opcode wire byte did not map to a known opcode.
    BadOpcode,
    /// Register wire byte was out of range.
    BadRegister,
    /// A constant-pool index was out of range.
    BadConstIndex,
    /// A jump target was out of range.
    BadJumpTarget,
    /// Trailing checksum did not match (corruption or wrong seed).
    BadChecksum,
}

/// The build-specific encoding schedule derived from a [`BuildSeed`].
#[derive(Debug, Clone)]
pub struct BuildKey {
    opcode_perm: [u8; NUM_OPS as usize],
    opcode_inv: [u8; NUM_OPS as usize],
    reg_perm: [u8; NUM_REGS],
    reg_inv: [u8; NUM_REGS],
    stream_key: u64,
}

impl BuildKey {
    /// Derives the full encoding schedule from `seed`.
    #[must_use]
    pub fn derive(seed: &BuildSeed) -> Self {
        let opcode_perm = permutation(subkey(seed, b"kseal/vmspike/opcode-perm"), NUM_OPS as usize);
        let reg_perm = permutation(subkey(seed, b"kseal/vmspike/reg-perm"), NUM_REGS);
        let stream_key = subkey(seed, b"kseal/vmspike/stream-key");

        let mut opcode_inv = [0u8; NUM_OPS as usize];
        for (tag, &wire) in opcode_perm.iter().enumerate() {
            opcode_inv[wire as usize] = tag as u8;
        }
        let mut reg_inv = [0u8; NUM_REGS];
        for (logical, &wire) in reg_perm.iter().enumerate() {
            reg_inv[wire as usize] = logical as u8;
        }

        let mut op = [0u8; NUM_OPS as usize];
        op.copy_from_slice(&opcode_perm);
        let mut rg = [0u8; NUM_REGS];
        rg.copy_from_slice(&reg_perm);

        BuildKey {
            opcode_perm: op,
            opcode_inv,
            reg_perm: rg,
            reg_inv,
            stream_key,
        }
    }
}

/// Encodes `program` into a per-build-polymorphic byte stream under `key`.
#[must_use]
pub fn encode(program: &Program, key: &BuildKey) -> Vec<u8> {
    let mut raw: Vec<u8> = Vec::new();
    raw.extend_from_slice(&MAGIC);
    raw.push(VERSION);

    raw.push(program.consts.len() as u8);
    for c in &program.consts {
        raw.extend_from_slice(&c.to_be_bytes());
    }

    raw.extend_from_slice(&(program.instrs.len() as u16).to_be_bytes());
    for instr in &program.instrs {
        raw.push(key.opcode_perm[instr.tag() as usize]);
        match *instr {
            Instr::LoadConst { dst, k } | Instr::MulConst { dst, k } => {
                raw.push(key.reg_perm[dst as usize]);
                raw.push(k);
            }
            Instr::LoadInput { dst, slot } => {
                raw.push(key.reg_perm[dst as usize]);
                raw.push(slot);
            }
            Instr::Xor { dst, src }
            | Instr::Add { dst, src }
            | Instr::Sub { dst, src }
            | Instr::Mul { dst, src }
            | Instr::And { dst, src }
            | Instr::Or { dst, src } => {
                raw.push(key.reg_perm[dst as usize]);
                raw.push(key.reg_perm[src as usize]);
            }
            Instr::XorShr { dst, shift }
            | Instr::Rotl { dst, shift }
            | Instr::Shl { dst, shift }
            | Instr::Shr { dst, shift }
            | Instr::Rotr { dst, shift } => {
                raw.push(key.reg_perm[dst as usize]);
                raw.push(shift);
            }
            Instr::JmpIfEnd { target } | Instr::Jmp { target } => {
                raw.extend_from_slice(&target.to_be_bytes());
            }
            Instr::LoadByte { dst } | Instr::Ret { src: dst } => {
                raw.push(key.reg_perm[dst as usize]);
            }
        }
    }

    let checksum = fnv1a64(&raw);
    raw.extend_from_slice(&checksum.to_be_bytes());

    for (i, b) in raw.iter_mut().enumerate() {
        *b ^= keystream_byte(key.stream_key, i);
    }
    raw
}

/// Decodes a byte stream produced by [`encode`] under the same `key`.
///
/// # Errors
/// Returns [`DecodeError`] on a truncated buffer, a bad magic/version/checksum
/// (the usual symptom of decoding with the wrong [`BuildSeed`]), or an
/// out-of-range operand.
pub fn decode(bytes: &[u8], key: &BuildKey) -> Result<Program, DecodeError> {
    let mut raw = bytes.to_vec();
    for (i, b) in raw.iter_mut().enumerate() {
        *b ^= keystream_byte(key.stream_key, i);
    }
    if raw.len() < 8 {
        return Err(DecodeError::TooShort);
    }
    // Verify the trailing checksum before trusting any field.
    let split = raw.len() - 8;
    let want = fnv1a64(&raw[..split]);
    let got = u64::from_be_bytes(raw[split..].try_into().map_err(|_| DecodeError::TooShort)?);
    if want != got {
        return Err(DecodeError::BadChecksum);
    }

    let mut r = Reader::new(&raw[..split]);
    if r.take(4)? != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if r.u8()? != VERSION {
        return Err(DecodeError::BadVersion);
    }

    let n_consts = r.u8()? as usize;
    let mut consts = Vec::with_capacity(n_consts);
    for _ in 0..n_consts {
        consts.push(r.u64()?);
    }

    let n_instrs = r.u16()? as usize;
    let mut instrs = Vec::with_capacity(n_instrs);
    for _ in 0..n_instrs {
        let wire = r.u8()?;
        if wire as usize >= key.opcode_inv.len() {
            return Err(DecodeError::BadOpcode);
        }
        let tag = key.opcode_inv[wire as usize];
        let instr = decode_instr(tag, &mut r, key, n_consts, n_instrs)?;
        instrs.push(instr);
    }

    Ok(Program { instrs, consts })
}

fn decode_reg(r: &mut Reader, key: &BuildKey) -> Result<u8, DecodeError> {
    let wire = r.u8()?;
    if wire as usize >= key.reg_inv.len() {
        return Err(DecodeError::BadRegister);
    }
    Ok(key.reg_inv[wire as usize])
}

fn decode_instr(
    tag: u8,
    r: &mut Reader,
    key: &BuildKey,
    n_consts: usize,
    n_instrs: usize,
) -> Result<Instr, DecodeError> {
    use super::isa::{
        TAG_ADD, TAG_AND, TAG_JMP, TAG_JMP_IF_END, TAG_LOAD_BYTE, TAG_LOAD_CONST, TAG_LOAD_INPUT,
        TAG_MUL, TAG_MUL_CONST, TAG_OR, TAG_RET, TAG_ROTL, TAG_ROTR, TAG_SHL, TAG_SHR, TAG_SUB,
        TAG_XOR, TAG_XOR_SHR,
    };
    let instr = match tag {
        TAG_LOAD_CONST => {
            let dst = decode_reg(r, key)?;
            let k = r.u8()?;
            if k as usize >= n_consts {
                return Err(DecodeError::BadConstIndex);
            }
            Instr::LoadConst { dst, k }
        }
        TAG_MUL_CONST => {
            let dst = decode_reg(r, key)?;
            let k = r.u8()?;
            if k as usize >= n_consts {
                return Err(DecodeError::BadConstIndex);
            }
            Instr::MulConst { dst, k }
        }
        TAG_XOR => {
            let dst = decode_reg(r, key)?;
            let src = decode_reg(r, key)?;
            Instr::Xor { dst, src }
        }
        TAG_ADD => {
            let dst = decode_reg(r, key)?;
            let src = decode_reg(r, key)?;
            Instr::Add { dst, src }
        }
        TAG_XOR_SHR => {
            let dst = decode_reg(r, key)?;
            let shift = r.u8()?;
            Instr::XorShr { dst, shift }
        }
        TAG_ROTL => {
            let dst = decode_reg(r, key)?;
            let shift = r.u8()?;
            Instr::Rotl { dst, shift }
        }
        TAG_JMP_IF_END => {
            let target = r.u16()?;
            if target as usize >= n_instrs {
                return Err(DecodeError::BadJumpTarget);
            }
            Instr::JmpIfEnd { target }
        }
        TAG_JMP => {
            let target = r.u16()?;
            if target as usize >= n_instrs {
                return Err(DecodeError::BadJumpTarget);
            }
            Instr::Jmp { target }
        }
        TAG_LOAD_BYTE => Instr::LoadByte {
            dst: decode_reg(r, key)?,
        },
        TAG_RET => Instr::Ret {
            src: decode_reg(r, key)?,
        },
        TAG_SUB => {
            let dst = decode_reg(r, key)?;
            let src = decode_reg(r, key)?;
            Instr::Sub { dst, src }
        }
        TAG_MUL => {
            let dst = decode_reg(r, key)?;
            let src = decode_reg(r, key)?;
            Instr::Mul { dst, src }
        }
        TAG_AND => {
            let dst = decode_reg(r, key)?;
            let src = decode_reg(r, key)?;
            Instr::And { dst, src }
        }
        TAG_OR => {
            let dst = decode_reg(r, key)?;
            let src = decode_reg(r, key)?;
            Instr::Or { dst, src }
        }
        TAG_SHL => {
            let dst = decode_reg(r, key)?;
            let shift = r.u8()?;
            Instr::Shl { dst, shift }
        }
        TAG_SHR => {
            let dst = decode_reg(r, key)?;
            let shift = r.u8()?;
            Instr::Shr { dst, shift }
        }
        TAG_ROTR => {
            let dst = decode_reg(r, key)?;
            let shift = r.u8()?;
            Instr::Rotr { dst, shift }
        }
        TAG_LOAD_INPUT => {
            let dst = decode_reg(r, key)?;
            let slot = r.u8()?;
            Instr::LoadInput { dst, slot }
        }
        _ => return Err(DecodeError::BadOpcode),
    };
    Ok(instr)
}

/// Encodes `program` directly from a [`BuildSeed`].
#[must_use]
pub fn encode_with_seed(program: &Program, seed: &BuildSeed) -> Vec<u8> {
    encode(program, &BuildKey::derive(seed))
}

/// Decodes a stream directly from a [`BuildSeed`].
///
/// # Errors
/// See [`decode`].
pub fn decode_with_seed(bytes: &[u8], seed: &BuildSeed) -> Result<Program, DecodeError> {
    decode(bytes, &BuildKey::derive(seed))
}

// --- in-repo, zero-dependency primitives ---

/// First 8 bytes of `SHA-256(label ‖ seed)` as a big-endian `u64`.
pub(crate) fn subkey(seed: &BuildSeed, label: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(label);
    h.update(seed.0);
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b)
}

/// SplitMix64 finalizer — the avalanche used to expand a 64-bit key.
fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Deterministic keystream byte at position `i` for a given `key`.
pub(crate) fn keystream_byte(key: u64, i: usize) -> u8 {
    let mixed = splitmix64(key ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    (mixed >> 24) as u8
}

/// Fisher–Yates permutation of `0..n` (n ≤ 255) driven by a SplitMix64 stream.
fn permutation(seed_word: u64, n: usize) -> Vec<u8> {
    let mut out: Vec<u8> = (0..n as u8).collect();
    let mut state = seed_word ^ 0x5DEE_CE66_D5B6_3C9D;
    let mut i = n;
    while i > 1 {
        i -= 1;
        state = splitmix64(state);
        let j = (state % (i as u64 + 1)) as usize;
        out.swap(i, j);
    }
    out
}

/// 64-bit FNV-1a over `bytes`.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Minimal bounds-checked big-endian byte reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::TooShort)?;
        let slice = self.buf.get(self.pos..end).ok_or(DecodeError::TooShort)?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::isa::lower_tag_mix;

    #[test]
    fn perms_are_valid_permutations() {
        let key = BuildKey::derive(&BuildSeed::from_u64(42));
        let mut ops = key.opcode_perm;
        ops.sort_unstable();
        assert_eq!(ops, core::array::from_fn::<u8, { NUM_OPS as usize }, _>(|i| i as u8));
        let mut regs = key.reg_perm;
        regs.sort_unstable();
        assert_eq!(regs, core::array::from_fn::<u8, NUM_REGS, _>(|i| i as u8));
    }

    #[test]
    fn encode_is_deterministic_for_a_fixed_seed() {
        let prog = lower_tag_mix().program;
        let seed = BuildSeed::from_u64(7);
        assert_eq!(encode_with_seed(&prog, &seed), encode_with_seed(&prog, &seed));
    }

    #[test]
    fn round_trip_decode_recovers_program() {
        let prog = lower_tag_mix().program;
        let seed = BuildSeed::from_u64(123);
        let bytes = encode_with_seed(&prog, &seed);
        let back = decode_with_seed(&bytes, &seed).unwrap();
        assert_eq!(back, prog);
    }

    #[test]
    fn different_seeds_produce_different_bytecode() {
        let prog = lower_tag_mix().program;
        let a = encode_with_seed(&prog, &BuildSeed::from_u64(1));
        let b = encode_with_seed(&prog, &BuildSeed::from_u64(2));
        assert_ne!(a, b);
    }

    #[test]
    fn decoding_with_the_wrong_seed_fails() {
        let prog = lower_tag_mix().program;
        let bytes = encode_with_seed(&prog, &BuildSeed::from_u64(1));
        // A devirtualizer for build #2 gets nothing from build #1's bytecode.
        assert!(decode_with_seed(&bytes, &BuildSeed::from_u64(2)).is_err());
    }
}
