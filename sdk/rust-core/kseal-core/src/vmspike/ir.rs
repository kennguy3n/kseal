//! The maintained source→bytecode lowering: a small expression IR plus an
//! automatic compiler that lowers it to [`super::isa`] VM bytecode.
//!
//! Phase 5.3 (the spike) hand-lowered exactly one function instruction by
//! instruction. That does not scale: every new virtualized routine would mean
//! hand-writing — and hand-auditing — another bytecode table. This module
//! replaces the hand table with a **compiler**:
//!
//! * [`Expr`] is a pure, side-effect-free expression tree over fixed-width
//!   64-bit values: constants, input words, and the integer/bitwise operators
//!   the extended ISA supports (add/sub/mul/xor/and/or/shift/rotate).
//! * [`eval`] is the *reference* interpreter — a direct, obviously-correct
//!   evaluation of an [`Expr`] in native Rust. It is the ground truth the
//!   virtualized program must reproduce bit-for-bit.
//! * [`register_need`] is a Sethi–Ullman-style analysis computing the exact
//!   number of registers the code generator will consume, so [`lower`] can
//!   reject an expression that would not fit the register bank *before* emitting
//!   anything (rather than faulting at run time).
//! * [`lower`] is the code generator: a single deterministic pass that emits VM
//!   instructions and a retrace entry per instruction, reusing the same
//!   [`super::isa`] `Builder` the hand-lowering uses. The result is a
//!   [`LoweredProgram`] that [`super::encode`] makes per-build-polymorphic and
//!   [`super::interp::run_ir`] executes.
//!
//! The whole module is safe Rust (no `unsafe`) and lives under the default-off
//! `vm-spike` feature, so it changes nothing in the standard build.

use super::isa::{Builder, Instr, LoweredProgram, NUM_REGS};

/// A pure integer/bitwise expression over 64-bit values.
///
/// The tree references inputs by slot ([`Expr::Input`]); the compiled program
/// reads those slots from the input-word bank passed to
/// [`super::interp::run_ir`]. Every operator has wrapping/defined semantics (see
/// [`eval`]) so lowering is total and never panics or traps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A 64-bit constant.
    Const(u64),
    /// The `slot`-th 64-bit input word.
    Input(u8),
    /// `a + b` (wrapping).
    Add(Box<Expr>, Box<Expr>),
    /// `a - b` (wrapping).
    Sub(Box<Expr>, Box<Expr>),
    /// `a * b` (wrapping).
    Mul(Box<Expr>, Box<Expr>),
    /// `a ^ b`.
    Xor(Box<Expr>, Box<Expr>),
    /// `a & b`.
    And(Box<Expr>, Box<Expr>),
    /// `a | b`.
    Or(Box<Expr>, Box<Expr>),
    /// `a << (n & 63)`.
    Shl(Box<Expr>, u8),
    /// `a >> (n & 63)` (logical).
    Shr(Box<Expr>, u8),
    /// `a.rotate_left(n & 63)`.
    Rotl(Box<Expr>, u8),
    /// `a.rotate_right(n & 63)`.
    Rotr(Box<Expr>, u8),
}

/// Why an [`Expr`] could not be lowered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    /// The expression's register need exceeds the VM's register bank.
    TooManyRegisters {
        /// Registers the code generator would need.
        need: usize,
        /// Registers the VM actually has ([`NUM_REGS`]).
        have: usize,
    },
    /// An [`Expr::Input`] referenced a slot `>= num_inputs`.
    InputSlotOutOfRange {
        /// The offending slot.
        slot: u8,
        /// The declared number of input words.
        num_inputs: u8,
    },
    /// The constant pool overflowed the `u8` index space (>256 distinct
    /// constants). The bounded generators never approach this.
    ConstPoolOverflow,
}

impl Expr {
    /// Convenience constructor for a boxed binary node's children.
    fn bx(e: Expr) -> Box<Expr> {
        Box::new(e)
    }
}

/// Reference evaluation of `expr` over the 64-bit input `words`.
///
/// This is the straightforward, human-auditable semantics the compiled VM
/// program must match exactly. Every operation is total: shifts and rotates
/// mask their amount into `0..64` and arithmetic wraps, mirroring the
/// interpreter in [`super::interp`].
///
/// Reads of an out-of-range input slot yield `0`; [`lower`] rejects such
/// expressions up front, so within a lowered program this branch is never hit.
#[must_use]
pub fn eval(expr: &Expr, words: &[u64]) -> u64 {
    match expr {
        Expr::Const(c) => *c,
        Expr::Input(slot) => words.get(*slot as usize).copied().unwrap_or(0),
        Expr::Add(a, b) => eval(a, words).wrapping_add(eval(b, words)),
        Expr::Sub(a, b) => eval(a, words).wrapping_sub(eval(b, words)),
        Expr::Mul(a, b) => eval(a, words).wrapping_mul(eval(b, words)),
        Expr::Xor(a, b) => eval(a, words) ^ eval(b, words),
        Expr::And(a, b) => eval(a, words) & eval(b, words),
        Expr::Or(a, b) => eval(a, words) | eval(b, words),
        Expr::Shl(a, n) => eval(a, words) << (u32::from(*n) & 63),
        Expr::Shr(a, n) => eval(a, words) >> (u32::from(*n) & 63),
        Expr::Rotl(a, n) => eval(a, words).rotate_left(u32::from(*n) & 63),
        Expr::Rotr(a, n) => eval(a, words).rotate_right(u32::from(*n) & 63),
    }
}

/// Whether `op` is commutative, so the code generator may evaluate its operands
/// in either order (used to place the heavier subtree first and cut register
/// pressure).
fn is_commutative(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Add(..) | Expr::Mul(..) | Expr::Xor(..) | Expr::And(..) | Expr::Or(..)
    )
}

/// The two child expressions of a binary node, or `None` for leaves/unary nodes.
fn binary_children(expr: &Expr) -> Option<(&Expr, &Expr)> {
    match expr {
        Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::Xor(a, b)
        | Expr::And(a, b)
        | Expr::Or(a, b) => Some((a, b)),
        _ => None,
    }
}

/// The child expression of a unary (shift/rotate) node, or `None` otherwise.
fn unary_child(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::Shl(a, _) | Expr::Shr(a, _) | Expr::Rotl(a, _) | Expr::Rotr(a, _) => Some(a),
        _ => None,
    }
}

/// The number of registers [`lower`] will consume to evaluate `expr`.
///
/// This is a Sethi–Ullman labelling specialized to the code generator below:
///
/// * A leaf (`Const`/`Input`) needs one register.
/// * A unary shift/rotate reuses its operand's register, so it needs exactly as
///   many registers as its operand.
/// * A binary node evaluates one operand into `dst` and the other into `dst+1`.
///   For a **commutative** op the generator evaluates the heavier child first,
///   giving `max(hi, lo + 1)` where `hi >= lo` are the children's needs. For the
///   non-commutative `Sub` the left operand must end up in `dst`, so the need is
///   `max(need(a), need(b) + 1)`.
///
/// Because the generator's register choices are exactly those modelled here,
/// `register_need(expr) <= NUM_REGS` is a sufficient and necessary condition for
/// lowering to fit the register bank.
#[must_use]
pub fn register_need(expr: &Expr) -> usize {
    if let Some(child) = unary_child(expr) {
        return register_need(child);
    }
    if let Some((a, b)) = binary_children(expr) {
        let (na, nb) = (register_need(a), register_need(b));
        return if is_commutative(expr) {
            let (hi, lo) = if na >= nb { (na, nb) } else { (nb, na) };
            hi.max(lo + 1)
        } else {
            na.max(nb + 1)
        };
    }
    1 // Const / Input
}

/// The largest input slot referenced by `expr`, if any.
fn max_input_slot(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Const(_) => None,
        Expr::Input(slot) => Some(*slot),
        Expr::Shl(a, _) | Expr::Shr(a, _) | Expr::Rotl(a, _) | Expr::Rotr(a, _) => {
            max_input_slot(a)
        }
        _ => {
            let (a, b) = binary_children(expr).expect("non-leaf, non-unary node is binary");
            match (max_input_slot(a), max_input_slot(b)) {
                (x, None) => x,
                (None, y) => y,
                (Some(x), Some(y)) => Some(x.max(y)),
            }
        }
    }
}

/// A short, build-invariant label for the source step a node lowers to. Recorded
/// in the retrace map so a symbolicated crash names the operation, not just a pc.
fn step_label(expr: &Expr) -> &'static str {
    match expr {
        Expr::Const(_) => "ir:const",
        Expr::Input(_) => "ir:input",
        Expr::Add(..) => "ir:add",
        Expr::Sub(..) => "ir:sub",
        Expr::Mul(..) => "ir:mul",
        Expr::Xor(..) => "ir:xor",
        Expr::And(..) => "ir:and",
        Expr::Or(..) => "ir:or",
        Expr::Shl(..) => "ir:shl",
        Expr::Shr(..) => "ir:shr",
        Expr::Rotl(..) => "ir:rotl",
        Expr::Rotr(..) => "ir:rotr",
    }
}

/// Lowers `expr` to a [`LoweredProgram`] computing `function(words) =
/// eval(expr, words)`.
///
/// `function` names the routine in the retrace map; `num_inputs` is how many
/// input words the program expects (slots `0..num_inputs`). The emitted program
/// is straight-line: it loads constants/inputs into registers, applies the
/// operators, and returns the root expression's value via [`Instr::Ret`].
///
/// Lowering is deterministic — the same `expr` always yields the same program —
/// which is what keeps the per-build encoding (and hence `build_hash`)
/// reproducible.
///
/// # Errors
/// Returns [`LowerError`] if the expression needs more registers than the VM
/// has, references an input slot `>= num_inputs`, or overflows the constant
/// pool.
pub fn lower(
    function: &'static str,
    num_inputs: u8,
    expr: &Expr,
) -> Result<LoweredProgram, LowerError> {
    let need = register_need(expr);
    if need > NUM_REGS {
        return Err(LowerError::TooManyRegisters {
            need,
            have: NUM_REGS,
        });
    }
    if let Some(slot) = max_input_slot(expr) {
        if slot >= num_inputs {
            return Err(LowerError::InputSlotOutOfRange { slot, num_inputs });
        }
    }

    let mut b = Builder::new(function, Vec::new());
    let mut next_id: u32 = 0;
    let result_reg = gen(&mut b, expr, 0, &mut next_id)?;
    // The return is its own retrace site, numbered after every expression node.
    b.emit(Instr::Ret { src: result_reg }, "ir:return", next_id);
    Ok(b.finish())
}

/// Recursively emits code leaving the value of `expr` in register `dst`,
/// returning that register. May clobber registers `dst..dst + register_need - 1`.
///
/// `next_id` hands out a pre-order node id per visited node; the id is recorded
/// as the retrace `source_line`, so a faulting pc resolves back to the exact IR
/// node that emitted it.
fn gen(b: &mut Builder, expr: &Expr, dst: u8, next_id: &mut u32) -> Result<u8, LowerError> {
    let id = *next_id;
    *next_id += 1;
    let step = step_label(expr);

    match expr {
        Expr::Const(c) => {
            let k = intern(b, *c)?;
            b.emit(Instr::LoadConst { dst, k }, step, id);
        }
        Expr::Input(slot) => {
            b.emit(Instr::LoadInput { dst, slot: *slot }, step, id);
        }
        Expr::Shl(a, n) => {
            gen(b, a, dst, next_id)?;
            b.emit(Instr::Shl { dst, shift: *n }, step, id);
        }
        Expr::Shr(a, n) => {
            gen(b, a, dst, next_id)?;
            b.emit(Instr::Shr { dst, shift: *n }, step, id);
        }
        Expr::Rotl(a, n) => {
            gen(b, a, dst, next_id)?;
            b.emit(Instr::Rotl { dst, shift: *n }, step, id);
        }
        Expr::Rotr(a, n) => {
            gen(b, a, dst, next_id)?;
            b.emit(Instr::Rotr { dst, shift: *n }, step, id);
        }
        _ => {
            let (a, c) = binary_children(expr).expect("remaining variants are binary");
            // Place the heavier child in `dst` so the lighter one fits in
            // `dst+1` (Sethi–Ullman). For commutative ops we may reorder freely;
            // for `Sub` the left operand must land in `dst`, so we never swap.
            let swap = is_commutative(expr) && register_need(c) > register_need(a);
            if swap {
                gen(b, c, dst, next_id)?;
                gen(b, a, dst + 1, next_id)?;
            } else {
                gen(b, a, dst, next_id)?;
                gen(b, c, dst + 1, next_id)?;
            }
            let instr = binary_instr(expr, dst, dst + 1);
            b.emit(instr, step, id);
        }
    }
    Ok(dst)
}

/// The VM instruction implementing binary `expr` as `reg[dst] OP= reg[src]`.
fn binary_instr(expr: &Expr, dst: u8, src: u8) -> Instr {
    match expr {
        Expr::Add(..) => Instr::Add { dst, src },
        Expr::Sub(..) => Instr::Sub { dst, src },
        Expr::Mul(..) => Instr::Mul { dst, src },
        Expr::Xor(..) => Instr::Xor { dst, src },
        Expr::And(..) => Instr::And { dst, src },
        Expr::Or(..) => Instr::Or { dst, src },
        _ => unreachable!("binary_instr called on non-binary node"),
    }
}

/// Interns `c` into the builder's constant pool, mapping the pool-overflow
/// assertion to a recoverable [`LowerError`].
fn intern(b: &mut Builder, c: u64) -> Result<u8, LowerError> {
    if b.const_pool_len() >= 256 {
        return Err(LowerError::ConstPoolOverflow);
    }
    Ok(b.intern_const(c))
}

// --- the representative routine wired end-to-end (Task C) ---

/// Number of 64-bit input words [`demo_cohort_native`] / [`demo_cohort_expr`]
/// consume.
pub const DEMO_COHORT_INPUTS: u8 = 3;

/// Reference implementation of the representative pure function the tier
/// virtualizes end-to-end behind `ObfuscationStrength::HIGH`.
///
/// It buckets a device into an opaque cohort id from `(device_hi, device_lo,
/// salt)` using only mixing arithmetic. It is deliberately **non-crypto and
/// cold**: it feeds no golden vector (no proof HMAC, signed-config signature, or
/// kill-switch preimage), so virtualizing it cannot perturb any pinned output.
/// It exists to prove the lowering is wired through `strength` selection, not to
/// protect a secret.
#[must_use]
pub fn demo_cohort_native(device_hi: u64, device_lo: u64, salt: u64) -> u64 {
    let mut acc = device_hi ^ 0x9E37_79B9_7F4A_7C15;
    acc = acc.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    acc ^= acc >> 33;
    acc = acc.wrapping_add(device_lo);
    acc = acc.rotate_left(27);
    acc ^= salt;
    acc = acc.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    acc ^= acc >> 29;
    acc
}

/// The [`Expr`] form of [`demo_cohort_native`]. `eval(demo_cohort_expr(), &[hi,
/// lo, salt])` equals `demo_cohort_native(hi, lo, salt)`, and so does the
/// lowered, encoded, decoded VM program — pinned by tests.
#[must_use]
pub fn demo_cohort_expr() -> Expr {
    use Expr::{Add, Const, Input, Mul, Rotl, Shr, Xor};
    let hi = || Expr::bx(Input(0));
    let lo = || Expr::bx(Input(1));
    let salt = || Expr::bx(Input(2));

    // acc = (device_hi ^ K0)
    let acc = Xor(hi(), Expr::bx(Const(0x9E37_79B9_7F4A_7C15)));
    // acc = acc * K1
    let acc = Mul(Expr::bx(acc), Expr::bx(Const(0xFF51_AFD7_ED55_8CCD)));
    // acc ^= acc >> 33
    let acc = Xor(Expr::bx(acc.clone()), Expr::bx(Shr(Expr::bx(acc), 33)));
    // acc += device_lo
    let acc = Add(Expr::bx(acc), lo());
    // acc = acc.rotate_left(27)
    let acc = Rotl(Expr::bx(acc), 27);
    // acc ^= salt
    let acc = Xor(Expr::bx(acc), salt());
    // acc = acc * K2
    let acc = Mul(Expr::bx(acc), Expr::bx(Const(0xC4CE_B9FE_1A85_EC53)));
    // acc ^= acc >> 29
    Xor(Expr::bx(acc.clone()), Expr::bx(Shr(Expr::bx(acc), 29)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmspike::{decode_with_seed, encode_with_seed, interp, BuildSeed};

    /// SplitMix64 — a tiny deterministic PRNG so the property tests need no dep.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// Generates a random expression of bounded depth over `num_inputs` slots.
    /// Depth bounds register need (`need <= depth + 1`), keeping it within the
    /// register bank without rejection.
    fn random_expr(rng: &mut Rng, depth: u8, num_inputs: u8) -> Expr {
        if depth == 0 || rng.next() % 5 == 0 {
            return if rng.next() & 1 == 0 {
                Expr::Const(rng.next())
            } else {
                Expr::Input((rng.next() % u64::from(num_inputs)) as u8)
            };
        }
        let a = Box::new(random_expr(rng, depth - 1, num_inputs));
        match rng.next() % 11 {
            0 => Expr::Add(a, Box::new(random_expr(rng, depth - 1, num_inputs))),
            1 => Expr::Sub(a, Box::new(random_expr(rng, depth - 1, num_inputs))),
            2 => Expr::Mul(a, Box::new(random_expr(rng, depth - 1, num_inputs))),
            3 => Expr::Xor(a, Box::new(random_expr(rng, depth - 1, num_inputs))),
            4 => Expr::And(a, Box::new(random_expr(rng, depth - 1, num_inputs))),
            5 => Expr::Or(a, Box::new(random_expr(rng, depth - 1, num_inputs))),
            6 => Expr::Shl(a, (rng.next() & 0x3f) as u8),
            7 => Expr::Shr(a, (rng.next() & 0x3f) as u8),
            8 => Expr::Rotl(a, (rng.next() & 0x3f) as u8),
            9 => Expr::Rotr(a, (rng.next() & 0x3f) as u8),
            _ => Expr::Xor(a, Box::new(random_expr(rng, depth - 1, num_inputs))),
        }
    }

    #[test]
    fn register_need_matches_lowered_register_use() {
        // The analysis must never under-count, or codegen would index past the
        // register bank. Cross-check against the actual max register emitted.
        let mut rng = Rng(0x1234_5678);
        for _ in 0..2000 {
            let num_inputs = 1 + (rng.next() % 4) as u8;
            let expr = random_expr(&mut rng, 6, num_inputs);
            let need = register_need(&expr);
            let lowered = lower("rn_probe", num_inputs, &expr).unwrap();
            let max_reg = lowered
                .program
                .instrs
                .iter()
                .map(max_dst_or_src)
                .max()
                .unwrap_or(0);
            assert!(
                usize::from(max_reg) < need.max(1),
                "need={need} but saw reg {max_reg}"
            );
            assert!(need <= NUM_REGS);
        }
    }

    fn max_dst_or_src(instr: &Instr) -> u8 {
        match *instr {
            Instr::LoadConst { dst, .. }
            | Instr::LoadInput { dst, .. }
            | Instr::MulConst { dst, .. }
            | Instr::XorShr { dst, .. }
            | Instr::Rotl { dst, .. }
            | Instr::Rotr { dst, .. }
            | Instr::Shl { dst, .. }
            | Instr::Shr { dst, .. }
            | Instr::LoadByte { dst } => dst,
            Instr::Xor { dst, src }
            | Instr::Add { dst, src }
            | Instr::Sub { dst, src }
            | Instr::Mul { dst, src }
            | Instr::And { dst, src }
            | Instr::Or { dst, src } => dst.max(src),
            Instr::Ret { src } => src,
            Instr::JmpIfEnd { .. } | Instr::Jmp { .. } => 0,
        }
    }

    #[test]
    fn lowered_vm_is_byte_identical_to_native_eval_over_thousands_of_cases() {
        let mut rng = Rng(0xDEAD_BEEF_0BAD_F00D);
        let seed = BuildSeed::from_u64(0x00C0_FFEE);
        let mut total = 0u32;
        for _ in 0..3000 {
            let num_inputs = 1 + (rng.next() % 4) as u8;
            let expr = random_expr(&mut rng, 7, num_inputs);
            let lowered = lower("prop", num_inputs, &expr).unwrap();
            // Round-trip through the per-build encoder, as a shipped build would.
            let program =
                decode_with_seed(&encode_with_seed(&lowered.program, &seed), &seed).unwrap();
            for _ in 0..8 {
                let words: Vec<u64> = (0..num_inputs).map(|_| rng.next()).collect();
                let want = eval(&expr, &words);
                let got = interp::run_ir(&program, &words).unwrap();
                assert_eq!(got, want, "expr={expr:?} words={words:?}");
                total += 1;
            }
        }
        assert!(total >= 24_000, "exercised {total} input vectors");
    }

    #[test]
    fn demo_cohort_expr_matches_native_and_virtualized() {
        let expr = demo_cohort_expr();
        let lowered = lower("demo_cohort", DEMO_COHORT_INPUTS, &expr).unwrap();
        let seed = BuildSeed::from_u64(0x5EED_C0DE);
        let program =
            decode_with_seed(&encode_with_seed(&lowered.program, &seed), &seed).unwrap();

        let mut rng = Rng(0xA5A5_5A5A);
        for _ in 0..5000 {
            let (hi, lo, salt) = (rng.next(), rng.next(), rng.next());
            let want = demo_cohort_native(hi, lo, salt);
            assert_eq!(eval(&expr, &[hi, lo, salt]), want);
            assert_eq!(interp::run_ir(&program, &[hi, lo, salt]).unwrap(), want);
        }
    }

    #[test]
    fn lowering_is_deterministic_but_encoding_is_per_build_polymorphic() {
        let expr = demo_cohort_expr();
        let a = lower("demo_cohort", DEMO_COHORT_INPUTS, &expr).unwrap();
        let b = lower("demo_cohort", DEMO_COHORT_INPUTS, &expr).unwrap();
        // Same IR ⇒ identical decoded program (reproducible build_hash input).
        assert_eq!(a.program, b.program);

        let seed_a = BuildSeed::from_u64(0x1111);
        let seed_b = BuildSeed::from_u64(0x2222);
        let bytes_a = encode_with_seed(&a.program, &seed_a);
        let bytes_b = encode_with_seed(&a.program, &seed_b);
        assert_ne!(bytes_a, bytes_b, "two seeds must yield different bytecode");
        // Deterministic per seed.
        assert_eq!(bytes_a, encode_with_seed(&a.program, &seed_a));

        // The correct seed decodes and runs; a wrong seed must fail to decode.
        assert!(decode_with_seed(&bytes_a, &seed_a).is_ok());
        assert!(decode_with_seed(&bytes_a, &seed_b).is_err());
    }

    #[test]
    fn rejects_input_slot_out_of_range() {
        let expr = Expr::Input(3);
        assert_eq!(
            lower("oob", 3, &expr).err(),
            Some(LowerError::InputSlotOutOfRange {
                slot: 3,
                num_inputs: 3
            })
        );
    }

    #[test]
    fn rejects_expression_that_overflows_the_register_bank() {
        // A right-leaning comb of non-commutative Subs forces need to grow by one
        // per level: need(Sub(a,b)) = max(need a, need b + 1).
        let mut e = Expr::Const(1);
        for _ in 0..NUM_REGS {
            e = Expr::Sub(Box::new(Expr::Const(0)), Box::new(e));
        }
        match lower("too_big", 1, &e) {
            Err(LowerError::TooManyRegisters { need, have }) => {
                assert!(need > have);
                assert_eq!(have, NUM_REGS);
            }
            other => panic!("expected TooManyRegisters, got {other:?}"),
        }
    }
}
