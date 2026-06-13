package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes

class DebugStripperTest {

    private fun classWithDebugInfo(): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "com/example/Sample", null, "java/lang/Object", null)
        cw.visitSource("Sample.kt", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null)
        mv.visitCode()
        val start = Label()
        mv.visitLabel(start)
        mv.visitLineNumber(7, start)
        mv.visitInsn(Opcodes.RETURN)
        val end = Label()
        mv.visitLabel(end)
        mv.visitLocalVariable("local", "I", null, start, end, 1)
        mv.visitMaxs(0, 2)
        mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    @Test
    fun `strips source, line numbers and local variables`() {
        val original = classWithDebugInfo()
        assertTrue(DebugStripper.hasDebugInfo(original), "fixture must contain debug info")

        val stripped = DebugStripper.strip(original)
        assertFalse(DebugStripper.hasDebugInfo(stripped), "stripped class must carry no debug info")
    }

    @Test
    fun `recognises class files`() {
        assertTrue(DebugStripper.isClassFile("Foo.class"))
        assertFalse(DebugStripper.isClassFile("module-info.class"))
        assertFalse(DebugStripper.isClassFile("Foo.kt"))
    }
}
