package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Exercises [BytecodeObfuscator] against a real, ASM-generated class: the
 * obfuscated bytecode is loaded by the JVM (which verifies stack-map frames),
 * invoked via reflection, and checked for behavioural equivalence, string
 * hiding, name/mapping preservation, determinism and per-seed polymorphism.
 */
class BytecodeObfuscatorTest {

    private val seedA = ByteArray(32) { it.toByte() }
    private val seedB = ByteArray(32) { (it * 7 + 1).toByte() }

    private val high = BytecodeObfuscator.Options(
        encryptStrings = true, opaquePredicates = true, opaqueDensity = 1.0, minStringLength = 2,
    )
    private val low = ObfuscationStrength.LOW.toOptions(emptySet())

    @Test
    fun `obfuscated class preserves behaviour and verifies under the JVM`() {
        val original = sampleClass()
        val result = BytecodeObfuscator(seedA, high).obfuscate(mapOf("io/kseal/sample/Sample.class" to original))

        val loader = DefiningLoader()
        result.decoderClass!!.let { (path, bytes) ->
            assertEquals("${BytecodeObfuscator.DECODER_INTERNAL_NAME}.class", path)
            loader.define("io.kseal.generated.KsealStrings", bytes)
        }
        val clazz = loader.define("io.kseal.sample.Sample", result.transformedClasses.getValue("io/kseal/sample/Sample.class"))

        // Behaviour is identical for every method (loading + invoking forces JVM verification).
        assertEquals("hello world secret value", clazz.getMethod("greet").invoke(null))
        assertEquals("positive branch string", clazz.getMethod("pick", Int::class.java).invoke(null, 5))
        assertEquals("negative branch string", clazz.getMethod("pick", Int::class.java).invoke(null, -5))
        assertEquals(30, clazz.getMethod("sum", Int::class.java, Int::class.java).invoke(null, 10, 20))
        assertEquals("input/suffix literal", clazz.getMethod("concat", String::class.java).invoke(null, "input/"))
        assertEquals(7L, clazz.getMethod("wide", Long::class.java, Double::class.java).invoke(null, 3L, 4.0))
    }

    @Test
    fun `string literals are removed from the constant pool`() {
        val original = sampleClass()
        assertTrue(containsAscii(original, "secret value"), "fixture must embed the plaintext")

        val result = BytecodeObfuscator(seedA, low).obfuscate(mapOf("S.class" to original))
        val obfuscated = result.transformedClasses.getValue("S.class")
        assertFalse(containsAscii(obfuscated, "secret value"), "plaintext must not survive in the obfuscated class")
        assertFalse(containsAscii(obfuscated, "positive branch string"), "branch-string plaintext must not survive")
        assertTrue(result.summary.stringLoadsRewritten >= 4)
        assertTrue(result.summary.uniqueStringsEncrypted >= 4)
    }

    @Test
    fun `names are preserved so the R8 mapping still resolves`() {
        val original = sampleClass()
        val result = BytecodeObfuscator(seedA, high).obfuscate(mapOf("S.class" to original))

        val before = membersOf(original)
        val after = membersOf(result.transformedClasses.getValue("S.class"))
        assertEquals(before, after, "no type/method/field may be renamed by the obfuscator")
    }

    @Test
    fun `output is deterministic for a fixed seed`() {
        val original = sampleClass()
        val first = BytecodeObfuscator(seedA, high).obfuscate(mapOf("S.class" to original))
        val second = BytecodeObfuscator(seedA, high).obfuscate(mapOf("S.class" to original))
        assertArrayEquals(first.transformedClasses.getValue("S.class"), second.transformedClasses.getValue("S.class"))
        assertArrayEquals(first.decoderClass!!.second, second.decoderClass!!.second)
    }

    @Test
    fun `different seeds produce different bytecode (per-build polymorphism)`() {
        val original = sampleClass()
        val a = BytecodeObfuscator(seedA, high).obfuscate(mapOf("S.class" to original))
        val b = BytecodeObfuscator(seedB, high).obfuscate(mapOf("S.class" to original))
        assertFalse(
            a.transformedClasses.getValue("S.class").contentEquals(b.transformedClasses.getValue("S.class")),
            "a new seed must re-key the transforms and change the bytecode",
        )
        // The decoder ciphertext is seed-derived, so it differs too.
        assertFalse(a.decoderClass!!.second.contentEquals(b.decoderClass!!.second))
    }

    @Test
    fun `low strength inserts no opaque predicates`() {
        val result = BytecodeObfuscator(seedA, low).obfuscate(mapOf("S.class" to sampleClass()))
        assertEquals(0, result.summary.opaquePredicatesInserted)
        assertTrue(result.summary.stringLoadsRewritten > 0)
    }

    @Test
    fun `high strength inserts opaque predicates while staying verifiable`() {
        val result = BytecodeObfuscator(seedA, high).obfuscate(mapOf("io/kseal/sample/Sample.class" to sampleClass()))
        assertTrue(result.summary.opaquePredicatesInserted > 0)
        // Already verified by the JVM in the behaviour test; assert the count is sane
        // (greet/pick/sum/concat/wide are eligible; <init> is excluded).
        assertTrue(result.summary.methodsWithOpaquePredicate in 1..6)
    }

    @Test
    fun `disabled options copy classes through unchanged`() {
        val original = sampleClass()
        val off = ObfuscationStrength.OFF.toOptions(emptySet())
        val result = BytecodeObfuscator(seedA, off).obfuscate(mapOf("S.class" to original))
        assertArrayEquals(original, result.transformedClasses.getValue("S.class"))
        assertEquals(null, result.decoderClass)
        assertFalse(result.summary.applied)
    }

    // ---- Helpers ---------------------------------------------------------

    private class DefiningLoader : ClassLoader(BytecodeObfuscatorTest::class.java.classLoader) {
        fun define(binaryName: String, bytes: ByteArray): Class<*> = defineClass(binaryName, bytes, 0, bytes.size)
    }

    /** True if the ASCII bytes of [needle] appear anywhere in [classBytes] (i.e. in the constant pool). */
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

                override fun visitField(a: Int, name: String, d: String, s: String?, value: Any?): org.objectweb.asm.FieldVisitor? {
                    members += "field:$name:$d"
                    return null
                }
            },
            0,
        )
        return members
    }

    /**
     * Generates a behaviourally-rich sample class (branches, varied arg types,
     * several string constants) so the obfuscator's frame insertion and string
     * rewriting are exercised end-to-end.
     */
    private fun sampleClass(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "io/kseal/sample/Sample", null, "java/lang/Object", null)

        cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "greet", "()Ljava/lang/String;", null, null).apply {
            visitCode()
            visitLdcInsn("hello world secret value")
            visitInsn(Opcodes.ARETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "pick", "(I)Ljava/lang/String;", null, null).apply {
            visitCode()
            val neg = org.objectweb.asm.Label()
            visitVarInsn(Opcodes.ILOAD, 0)
            visitJumpInsn(Opcodes.IFLE, neg)
            visitLdcInsn("positive branch string")
            visitInsn(Opcodes.ARETURN)
            visitLabel(neg)
            visitFrame(Opcodes.F_SAME, 0, null, 0, null)
            visitLdcInsn("negative branch string")
            visitInsn(Opcodes.ARETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "sum", "(II)I", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ILOAD, 0)
            visitVarInsn(Opcodes.ILOAD, 1)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "concat", "(Ljava/lang/String;)Ljava/lang/String;", null, null).apply {
            visitCode()
            visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder")
            visitInsn(Opcodes.DUP)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false)
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false)
            visitLdcInsn("suffix literal")
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        // Long + double args exercise the two-slot entry-frame locals.
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "wide", "(JD)J", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.LLOAD, 0)
            visitVarInsn(Opcodes.DLOAD, 2)
            visitInsn(Opcodes.D2L)
            visitInsn(Opcodes.LADD)
            visitInsn(Opcodes.LRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        cw.visitEnd()
        return cw.toByteArray()
    }
}
