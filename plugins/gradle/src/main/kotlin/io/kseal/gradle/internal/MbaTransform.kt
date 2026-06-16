package io.kseal.gradle.internal

import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode

/**
 * Light **mixed boolean-arithmetic (MBA)** substitution for simple 32-bit integer
 * operations, applied only at the strongest [ObfuscationStrength] tier.
 *
 * Each targeted operator is replaced in place by an arithmetically-equivalent
 * expression over `^ & | ~ + <<`, so a static reader can no longer pattern-match
 * the original operator while the observable result is **bit-for-bit identical**
 * for every input (the identities hold in two's-complement modular arithmetic,
 * including overflow):
 *
 * ```
 *  a + b  ≡  (a ^ b) + ((a & b) << 1)
 *  a - b  ≡  a + (~b) + 1
 *  a ^ b  ≡  (a | b) - (a & b)
 *  a | b  ≡  (a & b) + (a ^ b)
 *  a & b  ≡  ~(~a | ~b)
 *   -a    ≡  ~a + 1
 * ```
 *
 * Binary operators consume their two operands from the stack into two
 * method-scoped scratch locals (allocated above every original local, so they are
 * never live across a basic block boundary) and rebuild the value; the unary
 * negation rewrite is pure-stack. Because every rewrite is straight-line and
 * stack/locals-neutral at its boundaries, it composes cleanly with the
 * control-flow-flattening pass and needs no stack-map frame surgery.
 *
 * Intentionally scoped to `int`: wider/floating arithmetic, increments ([IINC])
 * and comparisons are left untouched — correctness over coverage.
 */
internal object MbaTransform {

    private val BINARY = setOf(
        Opcodes.IADD, Opcodes.ISUB, Opcodes.IXOR, Opcodes.IOR, Opcodes.IAND,
    )

    /**
     * Rewrites eligible integer operators in [method] in place.
     *
     * @return the number of operators substituted.
     */
    fun apply(method: MethodNode): Int {
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) return 0
        val insns = method.instructions
        if (insns.size() == 0) return 0

        // Two scratch slots above every original local; reused across all rewrites
        // in this method (each rewrite fully consumes them before the next runs).
        val scratchBase = method.maxLocals
        val targets = insns.toArray().filter { it is InsnNode && (it.opcode in BINARY || it.opcode == Opcodes.INEG) }

        var substitutions = 0
        for (node in targets) {
            val repl = when (node.opcode) {
                Opcodes.INEG -> negate()
                Opcodes.IADD -> binary(scratchBase, ::add)
                Opcodes.ISUB -> binary(scratchBase, ::subtract)
                Opcodes.IXOR -> binary(scratchBase, ::xor)
                Opcodes.IOR -> binary(scratchBase, ::or)
                Opcodes.IAND -> binary(scratchBase, ::and)
                else -> continue
            }
            insns.insert(node, repl)
            insns.remove(node)
            substitutions++
        }

        if (substitutions > 0) {
            method.maxLocals = maxOf(method.maxLocals, scratchBase + 2)
        }
        return substitutions
    }

    /** `-a ≡ ~a + 1` (pure stack: operand already on top). */
    private fun negate(): InsnList = InsnList().apply {
        add(InsnNode(Opcodes.ICONST_M1))
        add(InsnNode(Opcodes.IXOR))
        add(InsnNode(Opcodes.ICONST_1))
        add(InsnNode(Opcodes.IADD))
    }

    /**
     * Emits a binary rewrite: pops `b` then `a` from the stack into scratch slots
     * `t1`/`t0`, then appends [body] which rebuilds the value from `ILOAD t0/t1`.
     */
    private fun binary(scratchBase: Int, body: (t0: Int, t1: Int) -> InsnList): InsnList {
        val t0 = scratchBase
        val t1 = scratchBase + 1
        return InsnList().apply {
            add(VarInsnNode(Opcodes.ISTORE, t1)) // b (stack top)
            add(VarInsnNode(Opcodes.ISTORE, t0)) // a
            add(body(t0, t1))
        }
    }

    private fun load(t: Int) = VarInsnNode(Opcodes.ILOAD, t)

    /** `(a ^ b) + ((a & b) << 1)`. */
    private fun add(t0: Int, t1: Int): InsnList = InsnList().apply {
        add(load(t0)); add(load(t1)); add(InsnNode(Opcodes.IXOR))
        add(load(t0)); add(load(t1)); add(InsnNode(Opcodes.IAND))
        add(InsnNode(Opcodes.ICONST_1)); add(InsnNode(Opcodes.ISHL))
        add(InsnNode(Opcodes.IADD))
    }

    /** `a + (~b) + 1`. */
    private fun subtract(t0: Int, t1: Int): InsnList = InsnList().apply {
        add(load(t0))
        add(load(t1)); add(InsnNode(Opcodes.ICONST_M1)); add(InsnNode(Opcodes.IXOR))
        add(InsnNode(Opcodes.ICONST_1)); add(InsnNode(Opcodes.IADD))
        add(InsnNode(Opcodes.IADD))
    }

    /** `(a | b) - (a & b)`. */
    private fun xor(t0: Int, t1: Int): InsnList = InsnList().apply {
        add(load(t0)); add(load(t1)); add(InsnNode(Opcodes.IOR))
        add(load(t0)); add(load(t1)); add(InsnNode(Opcodes.IAND))
        add(InsnNode(Opcodes.ISUB))
    }

    /** `(a & b) + (a ^ b)`. */
    private fun or(t0: Int, t1: Int): InsnList = InsnList().apply {
        add(load(t0)); add(load(t1)); add(InsnNode(Opcodes.IAND))
        add(load(t0)); add(load(t1)); add(InsnNode(Opcodes.IXOR))
        add(InsnNode(Opcodes.IADD))
    }

    /** `~(~a | ~b)` (De Morgan). */
    private fun and(t0: Int, t1: Int): InsnList = InsnList().apply {
        add(load(t0)); add(InsnNode(Opcodes.ICONST_M1)); add(InsnNode(Opcodes.IXOR))
        add(load(t1)); add(InsnNode(Opcodes.ICONST_M1)); add(InsnNode(Opcodes.IXOR))
        add(InsnNode(Opcodes.IOR))
        add(InsnNode(Opcodes.ICONST_M1)); add(InsnNode(Opcodes.IXOR))
    }
}
