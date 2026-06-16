package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Exercises the HIGH-tier [ControlFlowFlattener] and [MbaTransform] passes through
 * [BytecodeObfuscator]. Every transformed class is loaded by the JVM (which fully
 * verifies stack-map frames) and invoked reflectively over a range of inputs, so a
 * flattened/substituted method must be **bit-for-bit behaviourally identical** to
 * the original or the test fails at verification or on a value mismatch.
 */
class ControlFlowFlatteningTest {

    private val seedA = ByteArray(32) { it.toByte() }
    private val seedB = ByteArray(32) { (it * 5 + 3).toByte() }

    /** MBA + flattening in isolation (no string encryption / opaque predicates). */
    private val flattenOnly = BytecodeObfuscator.Options(
        encryptStrings = false,
        opaquePredicates = false,
        opaqueDensity = 0.0,
        minStringLength = 2,
        mixedBooleanArithmetic = true,
        flattenControlFlow = true,
    )

    @Test
    fun `flattened and MBA-substituted methods keep identical behaviour and verify`() {
        val result = BytecodeObfuscator(seedA, flattenOnly)
            .obfuscate(mapOf(CLASS_PATH to sampleClass()))

        assertTrue(result.summary.methodsFlattened >= 3, "loopSum/classify/arith must flatten")
        assertTrue(result.summary.flattenedBlocks > result.summary.methodsFlattened)
        assertTrue(result.summary.mbaSubstitutions > 0, "int ops must be MBA-substituted")
        assertEquals(null, result.decoderClass, "no decoder when string encryption is off")

        val clazz = define(result)
        for (n in intArrayOf(-5, -1, 0, 1, 2, 3, 7, 12, 50)) {
            assertEquals(refLoopSum(n), clazz.getMethod("loopSum", Int::class.java).invoke(null, n), "loopSum($n)")
            assertEquals(refClassify(n), clazz.getMethod("classify", Int::class.java).invoke(null, n), "classify($n)")
        }
        for ((a, b) in PAIRS) {
            assertEquals(refMix(a, b), clazz.getMethod("mix", Int::class.java, Int::class.java).invoke(null, a, b), "mix($a,$b)")
        }
        for ((a, b) in PAIRS) {
            val c = a xor b
            assertEquals(
                refArith(a, b, c),
                clazz.getMethod("arith", Int::class.java, Int::class.java, Int::class.java).invoke(null, a, b, c),
                "arith($a,$b,$c)",
            )
        }
    }

    @Test
    fun `the full HIGH tier composes flattening, MBA, string encryption and opaque predicates`() {
        val high = ObfuscationStrength.HIGH.toOptions(emptySet())
        val result = BytecodeObfuscator(seedA, high).obfuscate(mapOf(CLASS_PATH to sampleClass()))

        assertTrue(result.summary.methodsFlattened >= 3)
        assertTrue(result.summary.mbaSubstitutions > 0)
        assertTrue(result.summary.opaquePredicatesInserted > 0)
        assertTrue(result.summary.stringLoadsRewritten > 0)

        // The branch-string plaintext must not survive the HIGH pipeline.
        val obfuscated = result.transformedClasses.getValue(CLASS_PATH)
        assertFalse(containsAscii(obfuscated, "zero"))

        val clazz = define(result)
        for (n in intArrayOf(-3, 0, 4)) {
            assertEquals(refLoopSum(n), clazz.getMethod("loopSum", Int::class.java).invoke(null, n))
            assertEquals(refClassify(n), clazz.getMethod("classify", Int::class.java).invoke(null, n))
        }
        for ((a, b) in PAIRS) {
            assertEquals(refMix(a, b), clazz.getMethod("mix", Int::class.java, Int::class.java).invoke(null, a, b))
        }
    }

    @Test
    fun `names are preserved so the R8 mapping still resolves`() {
        val original = sampleClass()
        val result = BytecodeObfuscator(seedA, flattenOnly).obfuscate(mapOf(CLASS_PATH to original))
        assertEquals(membersOf(original), membersOf(result.transformedClasses.getValue(CLASS_PATH)))
    }

    @Test
    fun `kept classes are excluded from flattening and MBA`() {
        val keepRules = KeepRules.parse("-keep class io.kseal.sample.Flatten { *; }")
        val options = flattenOnly.copy(keepRules = keepRules)
        val result = BytecodeObfuscator(seedA, options).obfuscate(mapOf(CLASS_PATH to sampleClass()))

        assertEquals(0, result.summary.methodsFlattened, "a kept class must not be flattened")
        assertEquals(0, result.summary.mbaSubstitutions, "a kept class must not be MBA-substituted")
        // The class is returned untouched by the tree pass (no transforms enabled).
        assertArrayEquals(sampleClass(), result.transformedClasses.getValue(CLASS_PATH))
    }

    @Test
    fun `kept method names are excluded from flattening and MBA`() {
        // Excluding loopSum + arith leaves only classify flattenable and mix MBA-only;
        // verifies per-method (not just per-class) keep granularity.
        val keepRules = KeepRules.parse("", extraNameGlobs = listOf("loopSum", "arith", "mix"))
        val options = flattenOnly.copy(keepRules = keepRules)
        val result = BytecodeObfuscator(seedA, options).obfuscate(mapOf(CLASS_PATH to sampleClass()))

        assertEquals(1, result.summary.methodsFlattened, "only classify should remain flattenable")

        val clazz = define(result)
        for (n in intArrayOf(-1, 0, 9)) {
            assertEquals(refClassify(n), clazz.getMethod("classify", Int::class.java).invoke(null, n))
            assertEquals(refLoopSum(n), clazz.getMethod("loopSum", Int::class.java).invoke(null, n))
        }
    }

    @Test
    fun `strength below HIGH neither flattens nor substitutes`() {
        for (strength in listOf(ObfuscationStrength.OFF, ObfuscationStrength.LOW, ObfuscationStrength.MEDIUM)) {
            val options = strength.toOptions(emptySet())
            assertFalse(options.flattenControlFlow, "$strength must not flatten")
            assertFalse(options.mixedBooleanArithmetic, "$strength must not MBA-substitute")
            val result = BytecodeObfuscator(seedA, options).obfuscate(mapOf(CLASS_PATH to sampleClass()))
            assertEquals(0, result.summary.methodsFlattened, "$strength flattened a method")
            assertEquals(0, result.summary.mbaSubstitutions, "$strength substituted an op")
        }
        assertTrue(ObfuscationStrength.HIGH.toOptions(emptySet()).flattenControlFlow)
        assertTrue(ObfuscationStrength.HIGH.toOptions(emptySet()).mixedBooleanArithmetic)
    }

    @Test
    fun `output is deterministic for a fixed seed and polymorphic across seeds`() {
        val original = sampleClass()
        val a1 = BytecodeObfuscator(seedA, flattenOnly).obfuscate(mapOf(CLASS_PATH to original))
        val a2 = BytecodeObfuscator(seedA, flattenOnly).obfuscate(mapOf(CLASS_PATH to original))
        assertArrayEquals(
            a1.transformedClasses.getValue(CLASS_PATH),
            a2.transformedClasses.getValue(CLASS_PATH),
            "a fixed seed must be reproducible",
        )
        val b = BytecodeObfuscator(seedB, flattenOnly).obfuscate(mapOf(CLASS_PATH to original))
        assertFalse(
            a1.transformedClasses.getValue(CLASS_PATH).contentEquals(b.transformedClasses.getValue(CLASS_PATH)),
            "a new seed must reshuffle the dispatcher and change the bytecode",
        )
    }

    // ---- Reference implementations (32-bit two's-complement, mirror the bytecode) ----

    private fun refLoopSum(n: Int): Int {
        var s = 0
        var i = 0
        while (i < n) { s += i; i++ }
        return s
    }

    private fun refClassify(n: Int): String = when {
        n < 0 -> "neg"
        n == 0 -> "zero"
        else -> "pos"
    }

    private fun refMix(a: Int, b: Int): Int {
        val x = (a + b) xor (a - b)
        val o = x or (a and b)
        return o - (-a)
    }

    private fun refArith(a: Int, b: Int, c: Int): Int {
        val r = if (a > b) a + b else a - b
        return r xor c
    }

    // ---- Helpers ---------------------------------------------------------

    private fun define(result: BytecodeObfuscator.Result): Class<*> {
        val loader = DefiningLoader()
        result.decoderClass?.let { (_, bytes) -> loader.define("io.kseal.generated.KsealStrings", bytes) }
        return loader.define("io.kseal.sample.Flatten", result.transformedClasses.getValue(CLASS_PATH))
    }

    private class DefiningLoader : ClassLoader(ControlFlowFlatteningTest::class.java.classLoader) {
        fun define(binaryName: String, bytes: ByteArray): Class<*> = defineClass(binaryName, bytes, 0, bytes.size)
    }

    private fun containsAscii(classBytes: ByteArray, needle: String): Boolean {
        val n = needle.toByteArray(Charsets.US_ASCII)
        if (n.isEmpty() || n.size > classBytes.size) return false
        outer@ for (i in 0..classBytes.size - n.size) {
            for (j in n.indices) if (classBytes[i + j] != n[j]) continue@outer
            return true
        }
        return false
    }

    private fun membersOf(classBytes: ByteArray): Set<String> {
        val members = sortedSetOf<String>()
        ClassReader(classBytes).accept(
            object : ClassVisitor(Opcodes.ASM9) {
                override fun visit(v: Int, a: Int, name: String, s: String?, sup: String?, i: Array<out String>?) {
                    members += "class:$name"
                }

                override fun visitMethod(a: Int, name: String, d: String, s: String?, e: Array<out String>?): MethodVisitor? {
                    members += "method:$name$d"
                    return null
                }
            },
            0,
        )
        return members
    }

    /**
     * A behaviourally-rich sample class built with computed frames (javac-style),
     * combining loops, multi-way branches and integer arithmetic so the flattener's
     * uniform-frame reasoning and the MBA substitution are both exercised.
     */
    private fun sampleClass(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "io/kseal/sample/Flatten", null, "java/lang/Object", null)

        cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        // int loopSum(int n) { int s=0; for (int i=0;i<n;i++) s+=i; return s; }
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "loopSum", "(I)I", null, null).apply {
            visitCode()
            val cond = Label()
            val end = Label()
            visitInsn(Opcodes.ICONST_0); visitVarInsn(Opcodes.ISTORE, 1) // s
            visitInsn(Opcodes.ICONST_0); visitVarInsn(Opcodes.ISTORE, 2) // i
            visitLabel(cond)
            visitVarInsn(Opcodes.ILOAD, 2); visitVarInsn(Opcodes.ILOAD, 0)
            visitJumpInsn(Opcodes.IF_ICMPGE, end)
            visitVarInsn(Opcodes.ILOAD, 1); visitVarInsn(Opcodes.ILOAD, 2); visitInsn(Opcodes.IADD); visitVarInsn(Opcodes.ISTORE, 1)
            visitVarInsn(Opcodes.ILOAD, 2); visitInsn(Opcodes.ICONST_1); visitInsn(Opcodes.IADD); visitVarInsn(Opcodes.ISTORE, 2)
            visitJumpInsn(Opcodes.GOTO, cond)
            visitLabel(end)
            visitVarInsn(Opcodes.ILOAD, 1); visitInsn(Opcodes.IRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        // String classify(int n) { if(n<0) "neg"; if(n==0) "zero"; else "pos"; }
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "classify", "(I)Ljava/lang/String;", null, null).apply {
            visitCode()
            val nonNeg = Label()
            val nonZero = Label()
            visitVarInsn(Opcodes.ILOAD, 0); visitJumpInsn(Opcodes.IFGE, nonNeg)
            visitLdcInsn("neg"); visitInsn(Opcodes.ARETURN)
            visitLabel(nonNeg)
            visitVarInsn(Opcodes.ILOAD, 0); visitJumpInsn(Opcodes.IFNE, nonZero)
            visitLdcInsn("zero"); visitInsn(Opcodes.ARETURN)
            visitLabel(nonZero)
            visitLdcInsn("pos"); visitInsn(Opcodes.ARETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        // int mix(int a,int b) — straight-line, exercises every MBA operator (not flattened: 1 block).
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "mix", "(II)I", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ILOAD, 0); visitVarInsn(Opcodes.ILOAD, 1); visitInsn(Opcodes.IADD) // a+b
            visitVarInsn(Opcodes.ILOAD, 0); visitVarInsn(Opcodes.ILOAD, 1); visitInsn(Opcodes.ISUB) // a-b
            visitInsn(Opcodes.IXOR)
            visitVarInsn(Opcodes.ILOAD, 0); visitVarInsn(Opcodes.ILOAD, 1); visitInsn(Opcodes.IAND) // a&b
            visitInsn(Opcodes.IOR)
            visitVarInsn(Opcodes.ILOAD, 0); visitInsn(Opcodes.INEG) // -a
            visitInsn(Opcodes.ISUB)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        // int arith(int a,int b,int c){ int r; if(a>b) r=a+b; else r=a-b; return r^c; }
        // Exercises a non-parameter local (r) that the prologue must default-init.
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "arith", "(III)I", null, null).apply {
            visitCode()
            val elseB = Label()
            val endB = Label()
            visitVarInsn(Opcodes.ILOAD, 0); visitVarInsn(Opcodes.ILOAD, 1); visitJumpInsn(Opcodes.IF_ICMPLE, elseB)
            visitVarInsn(Opcodes.ILOAD, 0); visitVarInsn(Opcodes.ILOAD, 1); visitInsn(Opcodes.IADD); visitVarInsn(Opcodes.ISTORE, 3)
            visitJumpInsn(Opcodes.GOTO, endB)
            visitLabel(elseB)
            visitVarInsn(Opcodes.ILOAD, 0); visitVarInsn(Opcodes.ILOAD, 1); visitInsn(Opcodes.ISUB); visitVarInsn(Opcodes.ISTORE, 3)
            visitLabel(endB)
            visitVarInsn(Opcodes.ILOAD, 3); visitVarInsn(Opcodes.ILOAD, 2); visitInsn(Opcodes.IXOR); visitInsn(Opcodes.IRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        cw.visitEnd()
        return cw.toByteArray()
    }

    private companion object {
        const val CLASS_PATH = "io/kseal/sample/Flatten.class"
        val PAIRS = listOf(
            10 to 20, -5 to 7, 0 to 0, 1 to -1, 123_456 to -987_654,
            Int.MAX_VALUE to 1, Int.MIN_VALUE to -1, -42 to -42,
        )
    }
}
