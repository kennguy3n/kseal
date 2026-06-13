package io.kseal.gradle.internal

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

/**
 * Strips debug metadata from JVM `.class` bytecode using ASM.
 *
 * Runs on the app's compiled classes before dexing and removes the
 * `SourceFile`, `SourceDebugExtension`, `LineNumberTable`, `LocalVariableTable`,
 * `LocalVariableTypeTable` and `MethodParameters` attributes — everything that
 * leaks source paths, original local-variable names and line numbers into the
 * shipped binary. `ClassReader.SKIP_DEBUG` drops the method-body debug
 * attributes; [visitSource] is additionally suppressed so the source filename is
 * not re-emitted. Functional behaviour and the public type/member surface are
 * untouched, so this never breaks the app; crash line numbers are recovered via
 * the preserved R8 mapping, not via in-binary debug info.
 */
internal object DebugStripper {

    private const val API = Opcodes.ASM9

    fun strip(classBytes: ByteArray): ByteArray {
        val reader = ClassReader(classBytes)
        // COMPUTE_MAXS is unnecessary (we copy, not rewrite, frames) — passing 0
        // preserves the original stack-map frames and is fastest.
        val writer = ClassWriter(0)
        val stripper = object : ClassVisitor(API, writer) {
            override fun visitSource(source: String?, debug: String?) {
                // Drop both SourceFile and SourceDebugExtension.
            }
        }
        reader.accept(stripper, ClassReader.SKIP_DEBUG)
        return writer.toByteArray()
    }

    fun isClassFile(name: String): Boolean =
        name.endsWith(".class", ignoreCase = true) && !name.endsWith("module-info.class")

    /** Test/diagnostic helper: true if the class still carries line-number debug info. */
    fun hasDebugInfo(classBytes: ByteArray): Boolean {
        var found = false
        val reader = ClassReader(classBytes)
        reader.accept(object : ClassVisitor(API) {
            override fun visitSource(source: String?, debug: String?) {
                if (source != null || debug != null) found = true
            }

            override fun visitMethod(
                access: Int,
                name: String?,
                descriptor: String?,
                signature: String?,
                exceptions: Array<out String>?,
            ): org.objectweb.asm.MethodVisitor {
                return object : org.objectweb.asm.MethodVisitor(API) {
                    override fun visitLineNumber(line: Int, start: org.objectweb.asm.Label?) {
                        found = true
                    }

                    override fun visitLocalVariable(
                        n: String?,
                        d: String?,
                        s: String?,
                        start: org.objectweb.asm.Label?,
                        end: org.objectweb.asm.Label?,
                        index: Int,
                    ) {
                        found = true
                    }
                }
            }
        }, 0)
        return found
    }
}
