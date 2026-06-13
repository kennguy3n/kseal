package io.kseal.gradle.internal

import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes

/**
 * Generates the runtime string-decoder class injected by [BytecodeObfuscator].
 *
 * The class is a single `public static String s(int)` plus two `byte[][]` tables
 * (ciphertext + per-entry keystream) built in `<clinit>`. Decoding is a constant
 * XOR over the embedded bytes, so it is allocation-light and adds no startup cost
 * (the tables initialise lazily on first class use). Byte payloads are carried as
 * Latin-1 string constants — a 1:1 byte↔char map that round-trips through
 * `getBytes(ISO_8859_1)` — which keeps the constant pool compact.
 *
 * Only JDK types are referenced, so this class is generated with
 * `COMPUTE_FRAMES`: the writer can resolve every `getCommonSuperClass` from its
 * own classloader, unlike the app classes (which may reference an absent
 * android.jar).
 */
internal object DecoderClassGenerator {

    private const val STANDARD_CHARSETS = "java/nio/charset/StandardCharsets"
    private const val CHARSET_DESC = "Ljava/nio/charset/Charset;"

    fun generate(table: BytecodeObfuscator.StringTable): ByteArray {
        val internalName = BytecodeObfuscator.DECODER_INTERNAL_NAME
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL or Opcodes.ACC_SUPER,
            internalName,
            null,
            "java/lang/Object",
            null,
        )
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "C", "[[B", null, null).visitEnd()
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "K", "[[B", null, null).visitEnd()

        emitClinit(cw, internalName, table)
        emitDecode(cw, internalName)
        emitPrivateCtor(cw)

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun emitClinit(cw: ClassWriter, owner: String, table: BytecodeObfuscator.StringTable) {
        val mv = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        mv.visitCode()
        initTable(mv, owner, "C", table.ciphertexts)
        initTable(mv, owner, "K", table.keys)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
    }

    private fun initTable(mv: org.objectweb.asm.MethodVisitor, owner: String, field: String, payloads: List<ByteArray>) {
        pushInt(mv, payloads.size)
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "[B")
        mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, field, "[[B")
        payloads.forEachIndexed { i, bytes ->
            mv.visitFieldInsn(Opcodes.GETSTATIC, owner, field, "[[B")
            pushInt(mv, i)
            mv.visitLdcInsn(latin1(bytes))
            mv.visitFieldInsn(Opcodes.GETSTATIC, STANDARD_CHARSETS, "ISO_8859_1", CHARSET_DESC)
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "getBytes", "($CHARSET_DESC)[B", false)
            mv.visitInsn(Opcodes.AASTORE)
        }
    }

    /** `public static String s(int i)` — XOR ciphertext with key, decode as UTF-8. */
    private fun emitDecode(cw: ClassWriter, owner: String) {
        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            BytecodeObfuscator.DECODER_METHOD,
            BytecodeObfuscator.DECODER_DESCRIPTOR,
            null,
            null,
        )
        mv.visitCode()
        // byte[] ct = C[i];  (local 1)
        mv.visitFieldInsn(Opcodes.GETSTATIC, owner, "C", "[[B")
        mv.visitVarInsn(Opcodes.ILOAD, 0)
        mv.visitInsn(Opcodes.AALOAD)
        mv.visitVarInsn(Opcodes.ASTORE, 1)
        // byte[] k = K[i];  (local 2)
        mv.visitFieldInsn(Opcodes.GETSTATIC, owner, "K", "[[B")
        mv.visitVarInsn(Opcodes.ILOAD, 0)
        mv.visitInsn(Opcodes.AALOAD)
        mv.visitVarInsn(Opcodes.ASTORE, 2)
        // byte[] o = new byte[ct.length];  (local 3)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitInsn(Opcodes.ARRAYLENGTH)
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        mv.visitVarInsn(Opcodes.ASTORE, 3)
        // for (int j = 0; j < ct.length; j++) o[j] = (byte)(ct[j] ^ k[j]);  (j = local 4)
        mv.visitInsn(Opcodes.ICONST_0)
        mv.visitVarInsn(Opcodes.ISTORE, 4)
        val loop = Label()
        val end = Label()
        mv.visitLabel(loop)
        mv.visitVarInsn(Opcodes.ILOAD, 4)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitInsn(Opcodes.ARRAYLENGTH)
        mv.visitJumpInsn(Opcodes.IF_ICMPGE, end)
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitVarInsn(Opcodes.ILOAD, 4)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitVarInsn(Opcodes.ILOAD, 4)
        mv.visitInsn(Opcodes.BALOAD)
        mv.visitVarInsn(Opcodes.ALOAD, 2)
        mv.visitVarInsn(Opcodes.ILOAD, 4)
        mv.visitInsn(Opcodes.BALOAD)
        mv.visitInsn(Opcodes.IXOR)
        mv.visitInsn(Opcodes.I2B)
        mv.visitInsn(Opcodes.BASTORE)
        mv.visitIincInsn(4, 1)
        mv.visitJumpInsn(Opcodes.GOTO, loop)
        mv.visitLabel(end)
        // return new String(o, StandardCharsets.UTF_8);
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/String")
        mv.visitInsn(Opcodes.DUP)
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitFieldInsn(Opcodes.GETSTATIC, STANDARD_CHARSETS, "UTF_8", CHARSET_DESC)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([B$CHARSET_DESC)V", false)
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
    }

    private fun emitPrivateCtor(cw: ClassWriter) {
        val mv = cw.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null)
        mv.visitCode()
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
    }

    /** Encodes arbitrary bytes as a Latin-1 string (1:1 byte↔char), round-tripping via `getBytes(ISO_8859_1)`. */
    private fun latin1(bytes: ByteArray): String {
        val chars = CharArray(bytes.size) { (bytes[it].toInt() and 0xff).toChar() }
        return String(chars)
    }

    private fun pushInt(mv: org.objectweb.asm.MethodVisitor, value: Int) {
        when {
            value in -1..5 -> mv.visitInsn(Opcodes.ICONST_0 + value)
            value in Byte.MIN_VALUE..Byte.MAX_VALUE -> mv.visitIntInsn(Opcodes.BIPUSH, value)
            value in Short.MIN_VALUE..Short.MAX_VALUE -> mv.visitIntInsn(Opcodes.SIPUSH, value)
            else -> mv.visitLdcInsn(value)
        }
    }
}
