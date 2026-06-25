package io.kseal.gradle.internal

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodNode

/**
 * Per-build, R8/mapping-aware **bytecode control-flow obfuscation** for Android
 * `.class` files, implemented with ASM.
 *
 * Two transforms compose, both keyed by the per-build polymorphism seed so every
 * build emits genuinely different bytecode while preserving program behaviour:
 *
 *  1. **String-constant encryption.** Every qualifying `String` literal loaded in
 *     a method body (`LDC`) is replaced by a call to a generated decoder
 *     ([DECODER_INTERNAL_NAME].`s(int)`). The plaintext no longer appears in the
 *     dex string pool; it is recovered at first use by XOR-ing the embedded
 *     ciphertext with an embedded, seed-derived keystream. Like the iOS string
 *     hardener this *raises the cost* of static extraction and makes a bypass
 *     decay per build — it is deliberately not unbreakable encryption (the key
 *     ships in the app; see `docs/build-hardening-android.md`).
 *
 *  2. **Opaque predicates (light control-flow obfuscation).** An always-true,
 *     seed-selected predicate is inserted at the entry of a seed-chosen subset of
 *     methods, guarding an unreachable bogus block. This perturbs the control-flow
 *     graph and basic-block layout a static disassembler reconstructs, without
 *     changing observable behaviour.
 *
 * **Why we stop short of VM/dispatcher obfuscation:** kseal deliberately avoids
 * heavy virtualization (bytecode→custom-VM) because it wrecks crash
 * symbolication, bloats and slows the app, and trades a one-time static-analysis
 * speed-bump for permanent runtime cost — the opposite of the SDK's performance
 * budget (see `ARCHITECTURE.md#what-kseal-deliberately-avoids`). These transforms are **name- and
 * mapping-preserving**: no type, method or field is renamed, so R8's `mapping.txt`
 * keeps resolving and crashes stay symbolicatable. Only a single new generated
 * class is added.
 *
 * Everything is deterministic given `(seed, options, input classes)`, so output
 * is reproducible and build-cacheable.
 */
internal class BytecodeObfuscator(
    private val seed: ByteArray,
    private val options: Options,
) {

    /** Strength-driven knobs; see [ObfuscationStrength.toOptions]. */
    data class Options(
        val encryptStrings: Boolean,
        val opaquePredicates: Boolean,
        /** Fraction (0.0–1.0) of eligible methods that receive an opaque predicate. */
        val opaqueDensity: Double,
        /** Minimum UTF-8 length for a string literal to be eligible for encryption. */
        val minStringLength: Int,
        /** Literal values (exact match) never encrypted (e.g. resource lookup keys). */
        val keepStrings: Set<String> = emptySet(),
        /** Substitute simple integer ops with MBA expressions (strongest tier only). */
        val mixedBooleanArithmetic: Boolean = false,
        /** Dispatcher-based control-flow flattening (strongest tier only). */
        val flattenControlFlow: Boolean = false,
        /**
         * `-keep*` rules: kept/entry classes (and their members) are excluded from
         * the MBA + flattening passes so reflection/JNI/serialization keep working.
         * The string-encryption and opaque-predicate passes are unaffected (they are
         * already name-preserving and honour [keepStrings]).
         */
        val keepRules: KeepRules? = null,
    )

    data class Summary(
        val classesProcessed: Int,
        val uniqueStringsEncrypted: Int,
        val stringLoadsRewritten: Int,
        val methodsWithOpaquePredicate: Int,
        val opaquePredicatesInserted: Int,
        val decoderClassInternalName: String?,
        val methodsFlattened: Int = 0,
        val flattenedBlocks: Int = 0,
        val mbaSubstitutions: Int = 0,
    ) {
        val applied: Boolean
            get() = stringLoadsRewritten > 0 || opaquePredicatesInserted > 0 ||
                methodsFlattened > 0 || mbaSubstitutions > 0
    }

    /** The full result of an obfuscation pass over a set of classes. */
    class Result(
        /** Transformed class bytes keyed by their original relative path. */
        val transformedClasses: Map<String, ByteArray>,
        /** The generated decoder class bytes + relative path, present iff strings were encrypted. */
        val decoderClass: Pair<String, ByteArray>?,
        val summary: Summary,
    )

    private val masterKey: ByteArray by lazy { Crypto.deriveKey(seed, "bytecode-string/v1") }
    private val flattener: ControlFlowFlattener by lazy { ControlFlowFlattener(masterKey) }

    /**
     * Obfuscates [classes] (relative path → bytecode). Non-`.class` entries must
     * be filtered by the caller. Returns transformed bytes plus the generated
     * decoder class (when string encryption produced any entries).
     */
    fun obfuscate(classes: Map<String, ByteArray>): Result {
        // Pass 0 (strongest tier only): MBA + control-flow flattening on the tree
        // representation, before string encryption so the string table and decoder
        // rewrites see the final instruction set. Purely additive — when neither is
        // enabled the input is returned untouched, keeping lower tiers byte-identical.
        var methodsFlattened = 0
        var flattenedBlocks = 0
        var mbaSubstitutions = 0
        val pre: Map<String, ByteArray> =
            if (options.mixedBooleanArithmetic || options.flattenControlFlow) {
                val out = LinkedHashMap<String, ByteArray>(classes.size)
                for ((path, bytes) in classes) {
                    val tree = treeTransform(bytes)
                    out[path] = tree.bytes
                    methodsFlattened += tree.methodsFlattened
                    flattenedBlocks += tree.flattenedBlocks
                    mbaSubstitutions += tree.mbaSubstitutions
                }
                out
            } else {
                classes
            }

        // Pass 1: collect every eligible string literal so each unique plaintext
        // gets a stable, deterministic index (sorted) shared across all classes.
        val table = if (options.encryptStrings) buildStringTable(pre.values) else StringTable.empty()

        var classesProcessed = 0
        var rewrites = 0
        var methodsWithPredicate = 0
        var predicates = 0

        val transformed = LinkedHashMap<String, ByteArray>(pre.size)
        for ((path, bytes) in pre.toSortedMap()) {
            val perClass = transformClass(bytes, table)
            transformed[path] = perClass.bytes
            classesProcessed++
            rewrites += perClass.stringLoadsRewritten
            methodsWithPredicate += perClass.methodsWithPredicate
            predicates += perClass.predicatesInserted
        }

        val decoder: Pair<String, ByteArray>? =
            if (table.isNotEmpty()) "$DECODER_INTERNAL_NAME.class" to DecoderClassGenerator.generate(table) else null

        val summary = Summary(
            classesProcessed = classesProcessed,
            uniqueStringsEncrypted = table.size,
            stringLoadsRewritten = rewrites,
            methodsWithOpaquePredicate = methodsWithPredicate,
            opaquePredicatesInserted = predicates,
            decoderClassInternalName = if (table.isNotEmpty()) DECODER_INTERNAL_NAME else null,
            methodsFlattened = methodsFlattened,
            flattenedBlocks = flattenedBlocks,
            mbaSubstitutions = mbaSubstitutions,
        )
        return Result(transformed, decoder, summary)
    }

    // ---- Tree pass: MBA + control-flow flattening (strongest tier) --------

    private class TreeResult(
        val bytes: ByteArray,
        val methodsFlattened: Int,
        val flattenedBlocks: Int,
        val mbaSubstitutions: Int,
    )

    private fun treeTransform(classBytes: ByteArray): TreeResult =
        try {
            treeTransformOrThrow(classBytes)
        } catch (t: Throwable) {
            // A single pathological class must never fail a tenant's build: fall
            // back to the untransformed bytes. The downstream string-encryption /
            // opaque-predicate pass still applies to it.
            TreeResult(classBytes, 0, 0, 0)
        }

    private fun treeTransformOrThrow(classBytes: ByteArray): TreeResult {
        val node = ClassNode(API)
        ClassReader(classBytes).accept(node, ClassReader.EXPAND_FRAMES)

        // KeepRules: a kept/entry class is excluded wholesale from both passes.
        // Keep specs use the dotted, source-level class name (e.g. `com.example.Api`),
        // so normalise ASM's `/`-separated internal name before matching.
        if (options.keepRules?.keepsClass(node.name.replace('/', '.')) == true) {
            return TreeResult(classBytes, 0, 0, 0)
        }

        var mba = 0
        if (options.mixedBooleanArithmetic) {
            for (method in node.methods) {
                if (skipForTree(method)) continue
                mba += MbaTransform.apply(method)
            }
        }

        // MBA can grow max stack/locals; round-trip through COMPUTE_MAXS so the
        // flattener's frame analysis observes correct sizes.
        var working = node
        if (mba > 0) {
            val normaliser = ClassWriter(ClassWriter.COMPUTE_MAXS)
            node.accept(normaliser)
            working = ClassNode(API)
            ClassReader(normaliser.toByteArray()).accept(working, ClassReader.EXPAND_FRAMES)
        }

        var methodsFlattened = 0
        var blocks = 0
        if (options.flattenControlFlow) {
            for (method in working.methods) {
                if (skipForTree(method)) continue
                val outcome = flattener.flatten(working.name, method)
                if (outcome.flattened) {
                    methodsFlattened++
                    blocks += outcome.blocks
                }
            }
        }

        if (mba == 0 && methodsFlattened == 0) return TreeResult(classBytes, 0, 0, 0)

        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        working.accept(writer)
        return TreeResult(writer.toByteArray(), methodsFlattened, blocks, mba)
    }

    private fun skipForTree(method: MethodNode): Boolean {
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) return true
        return options.keepRules?.keepsName(method.name) == true
    }

    // ---- String table ----------------------------------------------------

    private fun isEligibleString(value: String): Boolean {
        if (value.length < options.minStringLength) return false
        if (value in options.keepStrings) return false
        return true
    }

    private fun buildStringTable(classes: Collection<ByteArray>): StringTable {
        val unique = sortedSetOf<String>()
        for (bytes in classes) {
            ClassReader(bytes).accept(
                object : ClassVisitor(API) {
                    override fun visitMethod(a: Int, n: String?, d: String?, s: String?, e: Array<out String>?): MethodVisitor =
                        object : MethodVisitor(API) {
                            override fun visitLdcInsn(value: Any?) {
                                if (value is String && isEligibleString(value)) unique += value
                            }
                        }
                },
                ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES,
            )
        }
        if (unique.isEmpty()) return StringTable.empty()

        val index = HashMap<String, Int>(unique.size)
        val ciphertexts = ArrayList<ByteArray>(unique.size)
        val keys = ArrayList<ByteArray>(unique.size)
        unique.forEachIndexed { i, plaintext ->
            index[plaintext] = i
            val pt = plaintext.toByteArray(Charsets.UTF_8)
            val ks = keystream(i, pt.size)
            val ct = ByteArray(pt.size) { j -> (pt[j].toInt() xor ks[j].toInt()).toByte() }
            ciphertexts += ct
            keys += ks
        }
        return StringTable(index, ciphertexts, keys)
    }

    /** Deterministic per-index keystream: SHA-256(masterKey ‖ index ‖ counter) in CTR mode. */
    private fun keystream(index: Int, length: Int): ByteArray {
        if (length == 0) return ByteArray(0)
        val out = ByteArray(length)
        var pos = 0
        var counter = 0
        while (pos < length) {
            val block = Crypto.sha256(masterKey + intBytes(index) + intBytes(counter))
            val n = minOf(block.size, length - pos)
            System.arraycopy(block, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    private fun intBytes(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    // ---- Per-class transform ---------------------------------------------

    private class ClassTransformResult(
        val bytes: ByteArray,
        val stringLoadsRewritten: Int,
        val methodsWithPredicate: Int,
        val predicatesInserted: Int,
    )

    private fun transformClass(classBytes: ByteArray, table: StringTable): ClassTransformResult {
        val reader = ClassReader(classBytes)
        // EXPAND_FRAMES makes every stack-map frame independent (F_NEW), so the
        // opaque-predicate frame we insert at method entry composes correctly and
        // ASM re-compresses the rest on write. COMPUTE_MAXS recomputes max
        // stack/locals without the classpath-dependent frame computation that
        // would be unsafe for app classes referencing the (absent) android.jar.
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        var rewrites = 0
        var methodsWithPredicate = 0
        var predicates = 0

        val visitor = object : ClassVisitor(API, writer) {
            private var owner: String = "java/lang/Object"
            private var classVersion = Opcodes.V1_8

            override fun visit(version: Int, access: Int, name: String, sig: String?, sup: String?, ifaces: Array<out String>?) {
                owner = name
                classVersion = version and 0xffff
                super.visit(version, access, name, sig, sup, ifaces)
            }

            override fun visitMethod(access: Int, name: String, descriptor: String, sig: String?, exceptions: Array<out String>?): MethodVisitor {
                val mv = super.visitMethod(access, name, descriptor, sig, exceptions)
                val eligibleForPredicate = options.opaquePredicates &&
                    classVersion >= Opcodes.V1_6 &&
                    (access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) == 0 &&
                    name != "<init>" && name != "<clinit>" &&
                    selectForPredicate(owner, name, descriptor)
                return MethodObfuscator(
                    mv, table, owner, name, descriptor, access,
                    insertPredicate = eligibleForPredicate,
                    onRewrite = { rewrites++ },
                    onPredicate = { methodsWithPredicate++; predicates++ },
                )
            }
        }
        reader.accept(visitor, ClassReader.EXPAND_FRAMES)
        return ClassTransformResult(writer.toByteArray(), rewrites, methodsWithPredicate, predicates)
    }

    /** Deterministic, seed-bound decision whether a method receives an opaque predicate. */
    private fun selectForPredicate(owner: String, name: String, descriptor: String): Boolean {
        if (options.opaqueDensity >= 1.0) return true
        if (options.opaqueDensity <= 0.0) return false
        val digest = Crypto.sha256(masterKey + "$owner#$name$descriptor".toByteArray(Charsets.UTF_8))
        val bucket = (digest[0].toInt() and 0xff) / 256.0
        return bucket < options.opaqueDensity
    }

    /** Stable per-method predicate variant + constant, derived from the seed. */
    private fun predicateChoice(owner: String, name: String, descriptor: String): Pair<Int, Int> {
        val digest = Crypto.sha256(masterKey + "opaque:$owner#$name$descriptor".toByteArray(Charsets.UTF_8))
        val variant = (digest[1].toInt() and 0xff) % 3
        // A small non-negative constant keeps the always-true relations trivially valid.
        val constant = (digest[2].toInt() and 0x7f)
        return variant to constant
    }

    private inner class MethodObfuscator(
        delegate: MethodVisitor,
        private val table: StringTable,
        private val owner: String,
        private val methodName: String,
        private val descriptor: String,
        private val access: Int,
        private val insertPredicate: Boolean,
        private val onRewrite: () -> Unit,
        private val onPredicate: () -> Unit,
    ) : MethodVisitor(API, delegate) {

        override fun visitLdcInsn(value: Any?) {
            if (value is String && table.contains(value)) {
                pushInt(table.indexOf(value))
                super.visitMethodInsn(Opcodes.INVOKESTATIC, DECODER_INTERNAL_NAME, DECODER_METHOD, DECODER_DESCRIPTOR, false)
                onRewrite()
            } else {
                super.visitLdcInsn(value)
            }
        }

        override fun visitCode() {
            super.visitCode()
            if (!insertPredicate) return

            val realStart = Label()
            val bogus = Label()
            val (variant, c) = predicateChoice(owner, methodName, descriptor)
            // Emit an always-true predicate that branches to the real body; the
            // fallthrough bogus block is unreachable at runtime.
            when (variant) {
                0 -> { // c == c
                    pushInt(c); pushInt(c)
                    super.visitJumpInsn(Opcodes.IF_ICMPEQ, realStart)
                }
                1 -> { // c < c + 1
                    pushInt(c); pushInt(c + 1)
                    super.visitJumpInsn(Opcodes.IF_ICMPLT, realStart)
                }
                else -> { // c >= 0  (c is non-negative by construction)
                    pushInt(c)
                    super.visitJumpInsn(Opcodes.IFGE, realStart)
                }
            }
            super.visitLabel(bogus)
            // Unreachable: throwing null yields a verifiable, fall-through-free block.
            super.visitInsn(Opcodes.ACONST_NULL)
            super.visitInsn(Opcodes.ATHROW)

            super.visitLabel(realStart)
            // Explicit entry frame for the real body. EXPAND_FRAMES means we emit
            // F_NEW; the locals are exactly the method's incoming arguments.
            val locals = entryFrameLocals()
            super.visitFrame(Opcodes.F_NEW, locals.size, locals, 0, emptyArray())
            onPredicate()
        }

        private fun entryFrameLocals(): Array<Any> {
            val locals = ArrayList<Any>()
            if ((access and Opcodes.ACC_STATIC) == 0) locals += owner // `this`
            for (arg in Type.getArgumentTypes(descriptor)) {
                locals += when (arg.sort) {
                    Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> Opcodes.INTEGER
                    Type.FLOAT -> Opcodes.FLOAT
                    Type.LONG -> Opcodes.LONG
                    Type.DOUBLE -> Opcodes.DOUBLE
                    Type.ARRAY, Type.OBJECT -> arg.internalName ?: arg.descriptor
                    else -> Opcodes.TOP
                }
            }
            return locals.toTypedArray()
        }

        private fun pushInt(value: Int) {
            when {
                value in -1..5 -> super.visitInsn(Opcodes.ICONST_0 + value)
                value in Byte.MIN_VALUE..Byte.MAX_VALUE -> super.visitIntInsn(Opcodes.BIPUSH, value)
                value in Short.MIN_VALUE..Short.MAX_VALUE -> super.visitIntInsn(Opcodes.SIPUSH, value)
                else -> super.visitLdcInsn(value)
            }
        }
    }

    /** Immutable per-build string table: plaintext → index plus ciphertext/key bytes. */
    internal class StringTable(
        private val index: Map<String, Int>,
        val ciphertexts: List<ByteArray>,
        val keys: List<ByteArray>,
    ) {
        val size: Int get() = ciphertexts.size
        fun isNotEmpty(): Boolean = size > 0
        fun contains(value: String): Boolean = index.containsKey(value)
        fun indexOf(value: String): Int = index.getValue(value)

        companion object {
            fun empty(): StringTable = StringTable(emptyMap(), emptyList(), emptyList())
        }
    }

    companion object {
        private const val API = Opcodes.ASM9

        /** Internal name of the generated runtime string decoder. */
        const val DECODER_INTERNAL_NAME = "io/kseal/generated/KsealStrings"
        const val DECODER_METHOD = "s"
        const val DECODER_DESCRIPTOR = "(I)Ljava/lang/String;"
    }
}
