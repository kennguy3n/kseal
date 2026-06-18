//! The VM dispatch loop: executes a decoded [`Program`] over a byte input.
//!
//! This is the interpreter every virtualized call would run inside. It is
//! written in safe Rust (the crate is `#![forbid(unsafe_code)]`): register
//! indices are masked into range (the register bank size is a power of two) and
//! constant-pool / jump accesses are checked, so a malformed program faults with
//! a [`VmError`] carrying the faulting program counter rather than panicking.
//!
//! The captured [`VmFrame`] (the pc at the moment of a fault) is exactly what a
//! crash handler would record, and is the key the encrypted retrace map resolves
//! back to a source site (see [`super::retrace`]).

use super::isa::{Instr, Program, NUM_REGS};

/// A captured VM execution frame — the program counter at a point of interest
/// (typically a fault/"crash"). This is what symbolication resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmFrame {
    /// Instruction index the VM was executing.
    pub pc: u32,
}

/// Why a VM run stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmFault {
    /// The program counter ran past the end of the instruction stream without a
    /// [`Instr::Ret`].
    PcOutOfRange,
    /// A [`Instr::LoadConst`]/[`Instr::MulConst`] referenced a missing constant.
    BadConstIndex,
    /// A [`Instr::LoadByte`] ran with the input cursor already exhausted.
    InputExhausted,
    /// A [`Instr::LoadInput`] referenced an input-word slot that was not
    /// supplied.
    BadInputSlot,
    /// The step budget was exhausted (guards against malformed infinite loops).
    OutOfFuel,
}

/// A VM fault together with the frame at which it occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmError {
    /// The captured frame (faulting pc).
    pub frame: VmFrame,
    /// The reason execution stopped.
    pub fault: VmFault,
}

/// Default step budget multiplier: a well-formed program does `O(input.len())`
/// steps, so this generous cap only ever trips on a malformed program.
const FUEL_PER_BYTE: u64 = 64;
/// Fixed step budget added on top of the per-byte allowance.
const FUEL_BASE: u64 = 4096;

#[inline]
fn reg_index(r: u8) -> usize {
    // NUM_REGS is a power of two, so masking keeps the index in range with no
    // bounds panic. Decoded/lowered programs only ever use valid indices; the
    // mask is purely a belt-and-braces panic guard.
    (r as usize) & (NUM_REGS - 1)
}

/// Runs `program` over `input` with the given runtime `domain`, using the
/// default step budget. Returns the value of the program's return register.
///
/// # Errors
/// Returns a [`VmError`] (carrying the faulting [`VmFrame`]) if the program is
/// malformed: an out-of-range pc, a bad constant index, an over-read of the
/// input, or exhaustion of the step budget.
pub fn run(program: &Program, input: &[u8], domain: u64) -> Result<u64, VmError> {
    let fuel = FUEL_BASE + (input.len() as u64).saturating_mul(FUEL_PER_BYTE);
    run_with_fuel(program, input, domain, fuel)
}

/// Like [`run`] but with an explicit `fuel` (step) budget. Used by tests to
/// force — and then symbolicate — a deterministic fault.
///
/// # Errors
/// See [`run`].
pub fn run_with_fuel(
    program: &Program,
    input: &[u8],
    domain: u64,
    fuel: u64,
) -> Result<u64, VmError> {
    run_core(program, input, domain, &[], fuel)
}

/// Runs an [`super::ir`]-lowered `program` over 64-bit input `words`.
///
/// IR programs are straight-line (no `LoadByte`/`Jmp`), reading their inputs via
/// [`Instr::LoadInput`] rather than the byte cursor; this entry point supplies
/// the input-word bank. The default step budget is generous relative to the
/// fixed instruction count of a lowered expression.
///
/// # Errors
/// Returns a [`VmError`] for the same malformed-program reasons as [`run`], plus
/// [`VmFault::BadInputSlot`] if an instruction reads an unsupplied input slot.
pub fn run_ir(program: &Program, words: &[u64]) -> Result<u64, VmError> {
    let fuel = FUEL_BASE + (program.instrs.len() as u64).saturating_mul(FUEL_PER_BYTE);
    run_ir_with_fuel(program, words, fuel)
}

/// Like [`run_ir`] but with an explicit `fuel` (step) budget.
///
/// # Errors
/// See [`run_ir`].
pub fn run_ir_with_fuel(program: &Program, words: &[u64], fuel: u64) -> Result<u64, VmError> {
    run_core(program, &[], 0, words, fuel)
}

/// The shared dispatch core. `input`/`domain` drive the byte-oriented hand-
/// lowered routine; `words` drives [`Instr::LoadInput`] for IR-lowered programs.
/// Both input sources are always available, so a single loop serves both paths.
fn run_core(
    program: &Program,
    input: &[u8],
    domain: u64,
    words: &[u64],
    mut fuel: u64,
) -> Result<u64, VmError> {
    let mut regs = [0u64; NUM_REGS];
    regs[reg_index(super::isa::REG_DOMAIN)] = domain;
    let mut cursor: usize = 0;
    let mut pc: u32 = 0;

    loop {
        let frame = VmFrame { pc };
        if fuel == 0 {
            return Err(VmError {
                frame,
                fault: VmFault::OutOfFuel,
            });
        }
        fuel -= 1;

        let Some(instr) = program.instrs.get(pc as usize) else {
            return Err(VmError {
                frame,
                fault: VmFault::PcOutOfRange,
            });
        };

        match *instr {
            Instr::LoadConst { dst, k } => {
                let Some(&c) = program.consts.get(k as usize) else {
                    return Err(VmError {
                        frame,
                        fault: VmFault::BadConstIndex,
                    });
                };
                regs[reg_index(dst)] = c;
                pc += 1;
            }
            Instr::Xor { dst, src } => {
                regs[reg_index(dst)] ^= regs[reg_index(src)];
                pc += 1;
            }
            Instr::Add { dst, src } => {
                let v = regs[reg_index(dst)].wrapping_add(regs[reg_index(src)]);
                regs[reg_index(dst)] = v;
                pc += 1;
            }
            Instr::MulConst { dst, k } => {
                let Some(&c) = program.consts.get(k as usize) else {
                    return Err(VmError {
                        frame,
                        fault: VmFault::BadConstIndex,
                    });
                };
                let v = regs[reg_index(dst)].wrapping_mul(c);
                regs[reg_index(dst)] = v;
                pc += 1;
            }
            Instr::XorShr { dst, shift } => {
                let s = u32::from(shift) & 63;
                regs[reg_index(dst)] ^= regs[reg_index(dst)] >> s;
                pc += 1;
            }
            Instr::Rotl { dst, shift } => {
                let v = regs[reg_index(dst)].rotate_left(u32::from(shift) & 63);
                regs[reg_index(dst)] = v;
                pc += 1;
            }
            Instr::JmpIfEnd { target } => {
                if cursor >= input.len() {
                    pc = u32::from(target);
                } else {
                    pc += 1;
                }
            }
            Instr::LoadByte { dst } => {
                let Some(&b) = input.get(cursor) else {
                    return Err(VmError {
                        frame,
                        fault: VmFault::InputExhausted,
                    });
                };
                regs[reg_index(dst)] = u64::from(b);
                cursor += 1;
                pc += 1;
            }
            Instr::Jmp { target } => {
                pc = u32::from(target);
            }
            Instr::Ret { src } => {
                return Ok(regs[reg_index(src)]);
            }
            Instr::Sub { dst, src } => {
                let v = regs[reg_index(dst)].wrapping_sub(regs[reg_index(src)]);
                regs[reg_index(dst)] = v;
                pc += 1;
            }
            Instr::Mul { dst, src } => {
                let v = regs[reg_index(dst)].wrapping_mul(regs[reg_index(src)]);
                regs[reg_index(dst)] = v;
                pc += 1;
            }
            Instr::And { dst, src } => {
                regs[reg_index(dst)] &= regs[reg_index(src)];
                pc += 1;
            }
            Instr::Or { dst, src } => {
                regs[reg_index(dst)] |= regs[reg_index(src)];
                pc += 1;
            }
            Instr::Shl { dst, shift } => {
                let s = u32::from(shift) & 63;
                regs[reg_index(dst)] <<= s;
                pc += 1;
            }
            Instr::Shr { dst, shift } => {
                let s = u32::from(shift) & 63;
                regs[reg_index(dst)] >>= s;
                pc += 1;
            }
            Instr::Rotr { dst, shift } => {
                let v = regs[reg_index(dst)].rotate_right(u32::from(shift) & 63);
                regs[reg_index(dst)] = v;
                pc += 1;
            }
            Instr::LoadInput { dst, slot } => {
                let Some(&w) = words.get(slot as usize) else {
                    return Err(VmError {
                        frame,
                        fault: VmFault::BadInputSlot,
                    });
                };
                regs[reg_index(dst)] = w;
                pc += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::isa::{lower_tag_mix, native_tag_mix};

    #[test]
    fn interpreter_matches_native_on_samples() {
        let prog = lower_tag_mix().program;
        let cases: [(&[u8], u64); 4] = [
            (b"", 0),
            (b"a", 0xdead_beef),
            (b"kseal", 0x1122_3344_5566_7788),
            (&[0u8; 33], 1),
        ];
        for (input, domain) in cases {
            assert_eq!(run(&prog, input, domain), Ok(native_tag_mix(input, domain)));
        }
    }

    #[test]
    fn out_of_fuel_reports_a_frame() {
        let prog = lower_tag_mix().program;
        // One step is nowhere near enough; the VM must stop and hand back the pc
        // it was sitting on so a crash handler could record it.
        let err = run_with_fuel(&prog, b"some-input", 7, 1).unwrap_err();
        assert_eq!(err.fault, VmFault::OutOfFuel);
        assert!((err.frame.pc as usize) < prog.instrs.len());
    }
}
