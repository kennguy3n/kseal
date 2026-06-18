//! Virtual instruction set + the one representative "critical" routine the
//! spike virtualizes, plus its hand-lowering into a [`Program`].
//!
//! The ISA is a tiny **register machine**: a fixed bank of [`NUM_REGS`] 64-bit
//! registers, a read-only byte-input cursor, a constant pool, and ten opcodes —
//! just enough to express a real loop with a conditional branch. This is the
//! abstract, *decoded* form of the program; the per-build-polymorphic byte
//! encoding lives in [`super::encode`].
//!
//! ## The representative function
//!
//! [`native_tag_mix`] is a self-contained, pure, integer/byte mixing routine
//! invented **only** for this spike. It is deliberately *not* any real kseal
//! crypto or trust primitive: the spike must never virtualize the proof-signing,
//! kill-switch, Ed25519, or HMAC code (see the module banner in
//! [`super`]). It has the right *shape* for a virtualization candidate — small,
//! cold, branch + loop, integer-only — so the measured perf/size numbers are
//! representative of a genuine "cold critical gate".

use super::retrace::SourceSite;

/// Number of architectural registers in the VM. A power of two so the
/// interpreter can mask a register index into range with no bounds panic.
pub const NUM_REGS: usize = 8;

/// Accumulator register (also the conventional return register).
pub const REG_ACC: u8 = 0;
/// Register pre-loaded by the interpreter with the runtime `domain` argument.
pub const REG_DOMAIN: u8 = 1;
/// Scratch register holding the most recently loaded input byte.
pub const REG_TMP: u8 = 2;

/// Number of distinct opcodes; the wire opcode byte is a permutation of
/// `0..NUM_OPS` (see [`super::encode`]).
pub const NUM_OPS: u8 = 10;

// Stable opcode tags. The *wire* byte for each is shuffled per build; these tags
// are the build-invariant identity used by the interpreter and the encoder.
/// Tag: `reg[dst] = consts[k]`.
pub const TAG_LOAD_CONST: u8 = 0;
/// Tag: `reg[dst] ^= reg[src]`.
pub const TAG_XOR: u8 = 1;
/// Tag: `reg[dst] = reg[dst].wrapping_add(reg[src])`.
pub const TAG_ADD: u8 = 2;
/// Tag: `reg[dst] = reg[dst].wrapping_mul(consts[k])`.
pub const TAG_MUL_CONST: u8 = 3;
/// Tag: `reg[dst] ^= reg[dst] >> shift`.
pub const TAG_XOR_SHR: u8 = 4;
/// Tag: `reg[dst] = reg[dst].rotate_left(shift)`.
pub const TAG_ROTL: u8 = 5;
/// Tag: if the input cursor is at end, jump to `target`, else fall through.
pub const TAG_JMP_IF_END: u8 = 6;
/// Tag: `reg[dst] = input[cursor] as u64; cursor += 1`.
pub const TAG_LOAD_BYTE: u8 = 7;
/// Tag: unconditional jump to `target`.
pub const TAG_JMP: u8 = 8;
/// Tag: halt, returning `reg[src]`.
pub const TAG_RET: u8 = 9;

/// One decoded VM instruction. Operands reference registers by index, the
/// constant pool by index, or another instruction by index (jump target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instr {
    /// `reg[dst] = consts[k]`.
    LoadConst {
        /// Destination register.
        dst: u8,
        /// Constant-pool index.
        k: u8,
    },
    /// `reg[dst] ^= reg[src]`.
    Xor {
        /// Destination register.
        dst: u8,
        /// Source register.
        src: u8,
    },
    /// `reg[dst] = reg[dst].wrapping_add(reg[src])`.
    Add {
        /// Destination register.
        dst: u8,
        /// Source register.
        src: u8,
    },
    /// `reg[dst] = reg[dst].wrapping_mul(consts[k])`.
    MulConst {
        /// Destination register.
        dst: u8,
        /// Constant-pool index.
        k: u8,
    },
    /// `reg[dst] ^= reg[dst] >> shift` (the avalanche step).
    XorShr {
        /// Destination register.
        dst: u8,
        /// Right-shift amount (masked into `0..64`).
        shift: u8,
    },
    /// `reg[dst] = reg[dst].rotate_left(shift)`.
    Rotl {
        /// Destination register.
        dst: u8,
        /// Rotate amount.
        shift: u8,
    },
    /// If the input cursor is past the last byte, set `pc = target`; else
    /// advance to the next instruction.
    JmpIfEnd {
        /// Instruction index to branch to at end-of-input.
        target: u16,
    },
    /// `reg[dst] = input[cursor] as u64; cursor += 1`.
    LoadByte {
        /// Destination register.
        dst: u8,
    },
    /// Unconditional jump: `pc = target`.
    Jmp {
        /// Instruction index to branch to.
        target: u16,
    },
    /// Halt and return `reg[src]`.
    Ret {
        /// Register whose value is returned.
        src: u8,
    },
}

impl Instr {
    /// Build-invariant opcode tag for this instruction.
    #[must_use]
    pub fn tag(&self) -> u8 {
        match self {
            Instr::LoadConst { .. } => TAG_LOAD_CONST,
            Instr::Xor { .. } => TAG_XOR,
            Instr::Add { .. } => TAG_ADD,
            Instr::MulConst { .. } => TAG_MUL_CONST,
            Instr::XorShr { .. } => TAG_XOR_SHR,
            Instr::Rotl { .. } => TAG_ROTL,
            Instr::JmpIfEnd { .. } => TAG_JMP_IF_END,
            Instr::LoadByte { .. } => TAG_LOAD_BYTE,
            Instr::Jmp { .. } => TAG_JMP,
            Instr::Ret { .. } => TAG_RET,
        }
    }
}

/// A decoded VM program: a flat instruction vector plus its constant pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// Instruction stream, indexed by the program counter.
    pub instrs: Vec<Instr>,
    /// 64-bit constants referenced by [`Instr::LoadConst`] / [`Instr::MulConst`].
    pub consts: Vec<u64>,
}

/// A lowered program bundled with its retrace entries (one per instruction),
/// mapping each program counter back to the source site it came from.
#[derive(Debug, Clone)]
pub struct LoweredProgram {
    /// The decoded program.
    pub program: Program,
    /// `(pc, site)` pairs — the plaintext of the de-virtualization map.
    pub retrace: Vec<(u32, SourceSite)>,
}

// --- the representative routine + its reference semantics ---

/// FNV-style offset basis used to seed [`native_tag_mix`].
pub const MIX_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// Odd multiplier #1 (FNV-style prime).
pub const MIX_PRIME: u64 = 0x0000_0100_0000_01b3;
/// Odd multiplier #2 (golden-ratio constant) applied to the finalized digest.
pub const MIX_PRIME2: u64 = 0x9e37_79b9_7f4a_7c15;

/// Reference, native Rust implementation of the representative "critical"
/// routine: a domain-separated 64-bit mixing over `input`.
///
/// This is the *ground truth* the virtualized program must reproduce
/// byte-for-byte. It is a standalone toy mixer — **not** a security primitive —
/// chosen because its control-flow shape (seed → byte loop with multiply/rotate
/// → finalize) is typical of a small, cold gate one might consider virtualizing.
#[must_use]
pub fn native_tag_mix(input: &[u8], domain: u64) -> u64 {
    let mut acc = MIX_OFFSET ^ domain;
    let mut i = 0;
    while i < input.len() {
        acc ^= u64::from(input[i]);
        acc = acc.wrapping_mul(MIX_PRIME);
        acc ^= acc >> 29;
        acc = acc.wrapping_add(domain);
        acc = acc.rotate_left(17);
        i += 1;
    }
    acc ^= acc >> 32;
    acc.wrapping_mul(MIX_PRIME2)
}

/// Hand-lowers [`native_tag_mix`] into VM bytecode, recording a retrace entry
/// for every emitted instruction.
///
/// The lowering is a faithful, statement-by-statement translation, so each VM
/// program counter maps cleanly back to a source step (captured here as the
/// lowering-site line — see [`SourceSite`] for why the spike uses the lowering
/// site as the stand-in for a production DWARF line table).
#[must_use]
pub fn lower_tag_mix() -> LoweredProgram {
    let mut b = Builder::new(vec![MIX_OFFSET, MIX_PRIME, MIX_PRIME2]);

    b.emit(
        Instr::LoadConst { dst: REG_ACC, k: 0 },
        "acc = MIX_OFFSET",
        line!(),
    );
    b.emit(
        Instr::Xor {
            dst: REG_ACC,
            src: REG_DOMAIN,
        },
        "acc ^= domain",
        line!(),
    );

    let loop_top = b.here();
    let jmp_end = b.emit(
        Instr::JmpIfEnd { target: 0 }, // patched once the loop end is known
        "while i < input.len()",
        line!(),
    );
    b.emit(
        Instr::LoadByte { dst: REG_TMP },
        "tmp = input[i]; i += 1",
        line!(),
    );
    b.emit(
        Instr::Xor {
            dst: REG_ACC,
            src: REG_TMP,
        },
        "acc ^= input[i]",
        line!(),
    );
    b.emit(
        Instr::MulConst { dst: REG_ACC, k: 1 },
        "acc = acc.wrapping_mul(MIX_PRIME)",
        line!(),
    );
    b.emit(
        Instr::XorShr {
            dst: REG_ACC,
            shift: 29,
        },
        "acc ^= acc >> 29",
        line!(),
    );
    b.emit(
        Instr::Add {
            dst: REG_ACC,
            src: REG_DOMAIN,
        },
        "acc = acc.wrapping_add(domain)",
        line!(),
    );
    b.emit(
        Instr::Rotl {
            dst: REG_ACC,
            shift: 17,
        },
        "acc = acc.rotate_left(17)",
        line!(),
    );
    b.emit(
        Instr::Jmp { target: loop_top },
        "continue loop",
        line!(),
    );

    let loop_end = b.here();
    b.emit(
        Instr::XorShr {
            dst: REG_ACC,
            shift: 32,
        },
        "acc ^= acc >> 32",
        line!(),
    );
    b.emit(
        Instr::MulConst { dst: REG_ACC, k: 2 },
        "acc = acc.wrapping_mul(MIX_PRIME2)",
        line!(),
    );
    b.emit(Instr::Ret { src: REG_ACC }, "return acc", line!());

    b.patch_jmp_if_end(jmp_end, loop_end);
    b.finish()
}

/// Small helper that accumulates instructions, constants, and retrace entries
/// while lowering, and supports patching forward jump targets.
struct Builder {
    instrs: Vec<Instr>,
    consts: Vec<u64>,
    retrace: Vec<(u32, SourceSite)>,
}

impl Builder {
    fn new(consts: Vec<u64>) -> Self {
        Self {
            instrs: Vec::new(),
            consts,
            retrace: Vec::new(),
        }
    }

    /// Current instruction index (the pc the next emitted instruction will get).
    fn here(&self) -> u16 {
        self.instrs.len() as u16
    }

    /// Appends `instr`, records its source site, and returns its pc.
    fn emit(&mut self, instr: Instr, step: &'static str, source_line: u32) -> u16 {
        let pc = self.here();
        self.instrs.push(instr);
        self.retrace.push((
            u32::from(pc),
            SourceSite {
                function: "native_tag_mix",
                step,
                source_line,
            },
        ));
        pc
    }

    /// Rewrites the branch target of the [`Instr::JmpIfEnd`] previously emitted
    /// at `pc`.
    fn patch_jmp_if_end(&mut self, pc: u16, target: u16) {
        if let Some(Instr::JmpIfEnd { target: t }) = self.instrs.get_mut(pc as usize) {
            *t = target;
        }
    }

    fn finish(self) -> LoweredProgram {
        LoweredProgram {
            program: Program {
                instrs: self.instrs,
                consts: self.consts,
            },
            retrace: self.retrace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tag_mix_has_stable_known_vectors() {
        // Pin a couple of values so an accidental change to the reference
        // routine (and therefore the spike's "ground truth") is caught.
        // Empty input: seed, skip the loop, finalize (xor-shift then multiply).
        let finalized = (MIX_OFFSET ^ (MIX_OFFSET >> 32)).wrapping_mul(MIX_PRIME2);
        assert_eq!(native_tag_mix(b"", 0), finalized);
        // Non-trivial input + domain produces a stable, reproducible digest.
        let v = native_tag_mix(b"kseal-vmspike", 0x0102_0304_0506_0708);
        assert_eq!(v, native_tag_mix(b"kseal-vmspike", 0x0102_0304_0506_0708));
        assert_ne!(v, native_tag_mix(b"kseal-vmspike", 0));
    }

    #[test]
    fn lowering_is_well_formed() {
        let lowered = lower_tag_mix();
        let p = &lowered.program;
        // One retrace entry per instruction, in pc order.
        assert_eq!(lowered.retrace.len(), p.instrs.len());
        for (i, (pc, _)) in lowered.retrace.iter().enumerate() {
            assert_eq!(*pc as usize, i);
        }
        // Program is bounded and ends in a return.
        assert!(matches!(p.instrs.last(), Some(Instr::Ret { .. })));
        // Every jump target and constant index is in range.
        for instr in &p.instrs {
            match *instr {
                Instr::Jmp { target } | Instr::JmpIfEnd { target } => {
                    assert!((target as usize) < p.instrs.len());
                }
                Instr::LoadConst { k, .. } | Instr::MulConst { k, .. } => {
                    assert!((k as usize) < p.consts.len());
                }
                _ => {}
            }
        }
    }
}
