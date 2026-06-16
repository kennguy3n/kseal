package io.kseal.gradle.internal

import java.util.Random
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.FrameNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode
import org.objectweb.asm.tree.analysis.Analyzer
import org.objectweb.asm.tree.analysis.BasicInterpreter
import org.objectweb.asm.tree.analysis.BasicValue
import org.objectweb.asm.tree.analysis.Frame

/**
 * Dispatcher-based **control-flow flattening** (switch-over-basic-blocks).
 *
 * The method's basic blocks are detached from their original fall-through/branch
 * layout and re-dispatched through a single `LOOKUPSWITCH` keyed by a synthetic
 * `int` state local: every block, after running, writes the state of its
 * successor and jumps back to the dispatcher, which routes to the next block.
 * The seed-shuffled state ids and block emission order destroy the static CFG a
 * disassembler reconstructs, without changing observable behaviour.
 *
 * ### Correctness strategy (no classpath, app-class safe)
 * Flattening turns the dispatcher into a control-flow *merge* of every block, so
 * the verifier needs one stack-map frame that fits all of them. We compute a
 * single **uniform frame** for the dispatcher and every block leader and only
 * proceed when it is provably valid, otherwise the method is left untouched:
 *
 *  - Block-leader local types are read from **authoritative sources only** —
 *    javac's own `F_NEW` stack-map frames at jump targets, the method's entry
 *    frame, and exact within-block propagation for fall-through leaders (seeded
 *    from those authoritative frames; no merges, no classpath, no widening).
 *  - Every slot live at more than one leader must carry the **same** type at all
 *    of them (no widening); the operand stack must be **empty** at every leader.
 *  - Anything we cannot prove safe (try/catch, `jsr`/`ret`, existing switches,
 *    monitors, uninitialised refs across blocks, type conflicts, non-empty
 *    boundary stacks, too few blocks) makes the method ineligible.
 *
 * As a final guard the rewritten method is re-analysed; if anything is off the
 * original body is restored. The pass is **name/signature-preserving**, so R8's
 * `mapping.txt` keeps resolving and crash symbolication is unaffected.
 */
internal class ControlFlowFlattener(private val masterKey: ByteArray) {

    data class Outcome(val flattened: Boolean, val blocks: Int)

    /** Rewrites [method] in place when eligible; returns whether it was flattened. */
    fun flatten(owner: String, method: MethodNode): Outcome =
        try {
            Worker(owner, method, rngFor(owner, method)).run()
        } catch (t: Throwable) {
            // A flattener bug must never corrupt output: skip the method instead.
            Outcome(false, 0)
        }

    private fun rngFor(owner: String, method: MethodNode): Random {
        val digest = Crypto.sha256(masterKey + "flatten:$owner#${method.name}${method.desc}".toByteArray(Charsets.UTF_8))
        var seed = 0L
        for (i in 0 until 8) seed = (seed shl 8) or (digest[i].toLong() and 0xff)
        return Random(seed)
    }

    private class Worker(
        private val owner: String,
        private val method: MethodNode,
        private val rng: Random,
    ) {
        private val interp = PreciseInterpreter()

        fun run(): Outcome {
            if (!preCheck()) return NOT_FLATTENED

            val blocks = splitBlocks() ?: return NOT_FLATTENED
            if (blocks.size < MIN_BLOCKS) return NOT_FLATTENED

            val leaderFrames = computeLeaderFrames(blocks) ?: return NOT_FLATTENED
            val uniform = buildUniformLocals(blocks, leaderFrames) ?: return NOT_FLATTENED

            // The dispatcher is a control-flow merge of every block's exit, so the
            // uniform frame must be an *inductive invariant*: starting each block
            // from U must end (for blocks that re-enter the dispatcher) with locals
            // that still conform to U and an empty operand stack. This is the
            // soundness guarantee the lenient BasicInterpreter re-analysis cannot
            // make on its own (it would silently merge conflicting slot types that
            // the real JVM verifier rejects).
            if (!isInductive(blocks, uniform)) return NOT_FLATTENED

            val rebuilt = rebuild(blocks, uniform) ?: return NOT_FLATTENED

            // Commit, then re-analyse; restore on any structural problem.
            val savedInsns = method.instructions
            val savedMaxLocals = method.maxLocals
            val savedMaxStack = method.maxStack
            val savedLocals = method.localVariables
            val savedVisibleLvtAnnos = method.visibleLocalVariableAnnotations
            val savedInvisibleLvtAnnos = method.invisibleLocalVariableAnnotations

            method.instructions = rebuilt
            // The local-variable table and any local-variable *type* annotations
            // reference the original (now-discarded) labels; drop them so the
            // writer never emits a dangling label. Neither affects behaviour or
            // crash symbolication (class/method names are preserved).
            method.localVariables = null
            method.visibleLocalVariableAnnotations = null
            method.invisibleLocalVariableAnnotations = null
            method.maxLocals = uniform.stateSlot + 1
            method.maxStack = method.maxStack + 8

            if (!verifies()) {
                method.instructions = savedInsns
                method.localVariables = savedLocals
                method.visibleLocalVariableAnnotations = savedVisibleLvtAnnos
                method.invisibleLocalVariableAnnotations = savedInvisibleLvtAnnos
                method.maxLocals = savedMaxLocals
                method.maxStack = savedMaxStack
                return NOT_FLATTENED
            }
            return Outcome(true, blocks.size)
        }

        // ---- Eligibility -------------------------------------------------

        private fun preCheck(): Boolean {
            if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) return false
            if (method.name == "<init>" || method.name == "<clinit>") return false
            if (!method.tryCatchBlocks.isNullOrEmpty()) return false
            var realInsns = 0
            var insn = method.instructions.first
            while (insn != null) {
                when (insn.opcode) {
                    Opcodes.JSR, Opcodes.RET,
                    Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH,
                    Opcodes.MONITORENTER, Opcodes.MONITOREXIT,
                    -> return false
                }
                if (insn.opcode >= 0) realInsns++
                insn = insn.next
            }
            return realInsns >= MIN_REAL_INSNS
        }

        // ---- Basic-block reconstruction ----------------------------------

        /** A basic block: its instruction nodes plus a fresh entry label. */
        private inner class Block(val nodes: List<AbstractInsnNode>) {
            val label = LabelNode()
            var stateId = 0
            val firstReal: AbstractInsnNode? = nodes.firstOrNull { it.opcode >= 0 }
            val terminator: AbstractInsnNode? = nodes.lastOrNull { it.opcode >= 0 }
            val leaderNode: AbstractInsnNode = nodes.first()
            var fallsThrough = false
        }

        private fun splitBlocks(): List<Block>? {
            val list = method.instructions.toArray()
            if (list.isEmpty()) return null
            val leaders = HashSet<AbstractInsnNode>()
            leaders.add(list.first())
            for (insn in list) {
                when (insn) {
                    is JumpInsnNode -> {
                        leaders.add(insn.label)
                        insn.next?.let { leaders.add(it) }
                    }
                    else -> if (isExit(insn.opcode)) insn.next?.let { leaders.add(it) }
                }
            }
            // Build blocks as maximal runs starting at a leader node.
            val blocks = ArrayList<Block>()
            var current = ArrayList<AbstractInsnNode>()
            for (insn in list) {
                if (insn in leaders && current.isNotEmpty()) {
                    blocks.add(Block(current))
                    current = ArrayList()
                }
                current.add(insn)
            }
            if (current.isNotEmpty()) blocks.add(Block(current))
            // A block with no real instruction (only labels/lines) cannot be a
            // verifiable dispatch target.
            if (blocks.any { it.firstReal == null }) return null
            return blocks
        }

        // ---- Authoritative leader frames ---------------------------------

        private fun computeLeaderFrames(blocks: List<Block>): Map<Block, Frame<BasicValue>>? {
            val frames = LinkedHashMap<Block, Frame<BasicValue>>()
            var prevExit: Frame<BasicValue>? = null
            var prevFallsThrough = false

            for ((index, block) in blocks.withIndex()) {
                val entry: Frame<BasicValue> = when {
                    index == 0 -> entryFrame() ?: return null
                    frameNodeOf(block) != null -> fromFrameNode(frameNodeOf(block)!!) ?: return null
                    prevFallsThrough && prevExit != null -> prevExit
                    else -> return null // unreachable / undeterminable leader
                }
                if (entry.stackSize != 0) return null // boundaries must be empty-stack
                frames[block] = entry

                // Propagate exactly through the block to feed the next fall-through leader.
                val exit = Frame(entry)
                for (node in block.nodes) {
                    if (node.opcode < 0) continue
                    exit.execute(node, interp)
                }
                prevExit = exit
                prevFallsThrough = block.terminator?.let { fallsThrough(it.opcode) } ?: true
                block.fallsThrough = prevFallsThrough
            }
            return frames
        }

        private fun frameNodeOf(block: Block): FrameNode? {
            for (node in block.nodes) {
                if (node.opcode >= 0) return null // a real instruction precedes any frame
                if (node is FrameNode) return node
            }
            return null
        }

        private fun entryFrame(): Frame<BasicValue>? {
            val frame = blankFrame()
            var slot = 0
            if ((method.access and Opcodes.ACC_STATIC) == 0) {
                frame.setLocal(slot++, interp.newValue(Type.getObjectType(owner)))
            }
            for (arg in Type.getArgumentTypes(method.desc)) {
                frame.setLocal(slot++, interp.newValue(arg))
                if (arg.size == 2) frame.setLocal(slot++, BasicValue.UNINITIALIZED_VALUE)
            }
            return frame
        }

        private fun fromFrameNode(node: FrameNode): Frame<BasicValue>? {
            if (node.type != Opcodes.F_NEW) return null
            if (!node.stack.isNullOrEmpty()) return null
            val frame = blankFrame()
            var slot = 0
            for (item in node.local ?: emptyList<Any>()) {
                val value = frameItemToValue(item) ?: return null
                if (slot >= frame.locals) return null
                frame.setLocal(slot++, value)
                if (value.size == 2 && slot < frame.locals) frame.setLocal(slot++, BasicValue.UNINITIALIZED_VALUE)
            }
            return frame
        }

        private fun frameItemToValue(item: Any?): BasicValue? = when (item) {
            Opcodes.TOP -> BasicValue.UNINITIALIZED_VALUE
            Opcodes.INTEGER -> BasicValue.INT_VALUE
            Opcodes.FLOAT -> BasicValue.FLOAT_VALUE
            Opcodes.LONG -> BasicValue.LONG_VALUE
            Opcodes.DOUBLE -> BasicValue.DOUBLE_VALUE
            Opcodes.NULL -> NULL_VALUE
            is String -> BasicValue(Type.getObjectType(item))
            // UNINITIALIZED_THIS or an uninitialised-NEW (LabelNode) => unsupported.
            else -> null
        }

        private fun blankFrame(): Frame<BasicValue> {
            val frame = Frame<BasicValue>(method.maxLocals, method.maxStack)
            for (i in 0 until method.maxLocals) frame.setLocal(i, BasicValue.UNINITIALIZED_VALUE)
            return frame
        }

        // ---- Uniform frame -----------------------------------------------

        private inner class Uniform(val items: Map<Int, Any>, val stateSlot: Int)

        private fun buildUniformLocals(
            blocks: List<Block>,
            leaderFrames: Map<Block, Frame<BasicValue>>,
        ): Uniform? {
            val maxLocals = method.maxLocals
            val merged = HashMap<Int, BasicValue>()
            for (block in blocks) {
                val frame = leaderFrames.getValue(block)
                for (slot in 0 until maxLocals) {
                    val value = frame.getLocal(slot)
                    if (value == null || value == BasicValue.UNINITIALIZED_VALUE) continue
                    val existing = merged[slot]
                    if (existing == null) {
                        merged[slot] = value
                    } else {
                        val unified = unify(existing, value) ?: return null
                        merged[slot] = unified
                    }
                }
            }
            val items = HashMap<Int, Any>()
            for ((slot, value) in merged) {
                items[slot] = valueToFrameItem(value) ?: return null
            }
            return Uniform(items, maxLocals)
        }

        /**
         * Checks that [uniform] is an inductive invariant of the flattened CFG:
         * every block, executed from a frame seeded with U, must (when it re-enters
         * the dispatcher rather than leaving via return/throw) finish with an empty
         * operand stack and locals that still conform to U. Anything that does not
         * (e.g. a slot reused at incompatible types in disjoint scopes, which would
         * collide once all blocks share the dispatcher merge point) makes the method
         * ineligible — correctness over coverage.
         */
        private fun isInductive(blocks: List<Block>, uniform: Uniform): Boolean {
            for (block in blocks) {
                val frame = seedFrame(uniform)
                try {
                    for (node in block.nodes) {
                        if (node.opcode < 0) continue
                        frame.execute(node, interp)
                    }
                } catch (e: Exception) {
                    return false
                }
                // Blocks that leave the method never reach the dispatcher merge.
                val term = block.terminator
                if (term != null && isExit(term.opcode)) continue
                if (frame.stackSize != 0) return false
                for (slot in 0 until uniform.stateSlot) {
                    if (!exitConforms(frame.getLocal(slot), uniform.items[slot])) return false
                }
            }
            return true
        }

        /** A working frame whose locals are initialised to the uniform types. */
        private fun seedFrame(uniform: Uniform): Frame<BasicValue> {
            val frame = blankFrame()
            for ((slot, item) in uniform.items) {
                frameItemToValue(item)?.let { frame.setLocal(slot, it) }
            }
            return frame
        }

        /**
         * True when a block-exit [value] is assignable to the uniform slot type
         * [expected]. `null` expected means the slot is `TOP` in U (anything is
         * assignable to `TOP`); otherwise we require an exact match (the `null`
         * literal is assignable to any reference) — conservative, no classpath.
         */
        private fun exitConforms(value: BasicValue?, expected: Any?): Boolean {
            if (expected == null) return true
            if (value == null || value == BasicValue.UNINITIALIZED_VALUE) return false
            if (value == NULL_VALUE && expected is String) return true
            return valueToFrameItem(value) == expected
        }

        /** Two leader types for the same slot must coincide (no widening); null collapses to a ref. */
        private fun unify(a: BasicValue, b: BasicValue): BasicValue? {
            if (a == b) return a
            if (a == NULL_VALUE && isRef(b)) return b
            if (b == NULL_VALUE && isRef(a)) return a
            return null
        }

        private fun isRef(v: BasicValue): Boolean {
            val t = v.type ?: return false
            return t.sort == Type.OBJECT || t.sort == Type.ARRAY
        }

        private fun valueToFrameItem(value: BasicValue): Any? = when (value) {
            BasicValue.INT_VALUE -> Opcodes.INTEGER
            BasicValue.FLOAT_VALUE -> Opcodes.FLOAT
            BasicValue.LONG_VALUE -> Opcodes.LONG
            BasicValue.DOUBLE_VALUE -> Opcodes.DOUBLE
            NULL_VALUE -> Opcodes.NULL
            else -> value.type?.let { if (it.sort == Type.OBJECT || it.sort == Type.ARRAY) it.internalName else null }
        }

        // ---- Rebuild -----------------------------------------------------

        private fun rebuild(blocks: List<Block>, uniform: Uniform): InsnList? {
            assignStateIds(blocks)
            val byLeaderLabel = HashMap<LabelNode, Block>()
            for (block in blocks) {
                val leader = block.leaderNode
                if (leader is LabelNode) byLeaderLabel[leader] = block
            }
            val labelMap = HashMap<LabelNode, LabelNode>()
            var insn = method.instructions.first
            while (insn != null) {
                if (insn is LabelNode) labelMap[insn] = LabelNode()
                insn = insn.next
            }

            val out = InsnList()

            // Entry prologue: initialise non-parameter uniform slots to defaults so
            // the dispatcher's uniform frame is satisfied on first entry.
            val paramSlots = parameterSlots()
            for ((slot, item) in uniform.items.toSortedMap()) {
                if (slot in paramSlots) continue
                appendDefaultStore(out, slot, item)
            }
            pushInt(out, blocks.first().stateId)
            out.add(VarInsnNode(Opcodes.ISTORE, uniform.stateSlot))
            val dispatch = LabelNode()
            out.add(JumpInsnNode(Opcodes.GOTO, dispatch))

            // Dispatcher.
            val frameLocals = uniformLocalsArray(uniform)
            out.add(dispatch)
            out.add(FrameNode(Opcodes.F_NEW, frameLocals.size, frameLocals, 0, emptyArray()))
            out.add(VarInsnNode(Opcodes.ILOAD, uniform.stateSlot))
            val sorted = blocks.sortedBy { it.stateId }
            val keys = IntArray(sorted.size) { sorted[it].stateId }
            val labels = Array(sorted.size) { sorted[it].label }
            out.add(LookupSwitchInsnNode(blocks.first().label, keys, labels))

            // Blocks, emitted in a shuffled order.
            val emitOrder = blocks.toMutableList().also { shuffle(it) }
            for (block in emitOrder) {
                out.add(block.label)
                out.add(FrameNode(Opcodes.F_NEW, frameLocals.size, frameLocals, 0, emptyArray()))
                appendBlockBody(out, block, labelMap)
                if (!appendTerminator(out, block, blocks, byLeaderLabel, uniform, dispatch, frameLocals)) return null
            }
            return out
        }

        private fun appendBlockBody(out: InsnList, block: Block, labelMap: Map<LabelNode, LabelNode>) {
            val term = block.terminator
            val skipTerm = term != null && (term is JumpInsnNode || isExit(term.opcode))
            for (node in block.nodes) {
                if (node is FrameNode) continue
                if (skipTerm && node === term) continue
                out.add(node.clone(labelMap))
            }
        }

        private fun appendTerminator(
            out: InsnList,
            block: Block,
            blocks: List<Block>,
            byLeaderLabel: Map<LabelNode, Block>,
            uniform: Uniform,
            dispatch: LabelNode,
            frameLocals: Array<Any>,
        ): Boolean {
            val term = block.terminator
            val index = blocks.indexOf(block)
            val fallThroughBlock = blocks.getOrNull(index + 1)
            when {
                term is JumpInsnNode && term.opcode == Opcodes.GOTO -> {
                    val target = byLeaderLabel[term.label] ?: return false
                    appendGotoState(out, target, uniform, dispatch)
                }
                term is JumpInsnNode -> { // conditional
                    val target = byLeaderLabel[term.label] ?: return false
                    val fall = fallThroughBlock ?: return false
                    val thenLabel = LabelNode()
                    out.add(JumpInsnNode(term.opcode, thenLabel))
                    appendGotoState(out, fall, uniform, dispatch)
                    out.add(thenLabel)
                    out.add(FrameNode(Opcodes.F_NEW, frameLocals.size, frameLocals, 0, emptyArray()))
                    appendGotoState(out, target, uniform, dispatch)
                }
                term != null && isExit(term.opcode) -> {
                    out.add(term.clone(emptyMap())) // return/throw: control leaves the method
                }
                else -> { // straight-line fall-through
                    val fall = fallThroughBlock ?: return false
                    appendGotoState(out, fall, uniform, dispatch)
                }
            }
            return true
        }

        private fun appendGotoState(out: InsnList, target: Block, uniform: Uniform, dispatch: LabelNode) {
            pushInt(out, target.stateId)
            out.add(VarInsnNode(Opcodes.ISTORE, uniform.stateSlot))
            out.add(JumpInsnNode(Opcodes.GOTO, dispatch))
        }

        private fun appendDefaultStore(out: InsnList, slot: Int, item: Any) {
            when (item) {
                Opcodes.INTEGER -> { out.add(InsnNode(Opcodes.ICONST_0)); out.add(VarInsnNode(Opcodes.ISTORE, slot)) }
                Opcodes.FLOAT -> { out.add(InsnNode(Opcodes.FCONST_0)); out.add(VarInsnNode(Opcodes.FSTORE, slot)) }
                Opcodes.LONG -> { out.add(InsnNode(Opcodes.LCONST_0)); out.add(VarInsnNode(Opcodes.LSTORE, slot)) }
                Opcodes.DOUBLE -> { out.add(InsnNode(Opcodes.DCONST_0)); out.add(VarInsnNode(Opcodes.DSTORE, slot)) }
                else -> { out.add(InsnNode(Opcodes.ACONST_NULL)); out.add(VarInsnNode(Opcodes.ASTORE, slot)) }
            }
        }

        private fun parameterSlots(): Set<Int> {
            val slots = HashSet<Int>()
            var slot = 0
            if ((method.access and Opcodes.ACC_STATIC) == 0) slots.add(slot++)
            for (arg in Type.getArgumentTypes(method.desc)) {
                slots.add(slot)
                slot += arg.size
            }
            return slots
        }

        private fun uniformLocalsArray(uniform: Uniform): Array<Any> {
            val out = ArrayList<Any>()
            var slot = 0
            while (slot <= uniform.stateSlot) {
                val item: Any = if (slot == uniform.stateSlot) Opcodes.INTEGER else uniform.items[slot] ?: Opcodes.TOP
                out.add(item)
                slot += if (item == Opcodes.LONG || item == Opcodes.DOUBLE) 2 else 1
            }
            return out.toTypedArray()
        }

        private fun assignStateIds(blocks: List<Block>) {
            val used = HashSet<Int>()
            for (block in blocks) {
                var id: Int
                do {
                    id = rng.nextInt(0x40000000)
                } while (!used.add(id))
                block.stateId = id
            }
        }

        private fun <T> shuffle(list: MutableList<T>) {
            for (i in list.size - 1 downTo 1) {
                val j = rng.nextInt(i + 1)
                val tmp = list[i]; list[i] = list[j]; list[j] = tmp
            }
        }

        private fun pushInt(out: InsnList, value: Int) {
            when {
                value in -1..5 -> out.add(InsnNode(Opcodes.ICONST_0 + value))
                value in Byte.MIN_VALUE..Byte.MAX_VALUE -> out.add(IntInsnNode(Opcodes.BIPUSH, value))
                value in Short.MIN_VALUE..Short.MAX_VALUE -> out.add(IntInsnNode(Opcodes.SIPUSH, value))
                else -> out.add(LdcInsnNode(value))
            }
        }

        private fun verifies(): Boolean = try {
            Analyzer(BasicInterpreter()).analyze(owner, method)
            true
        } catch (t: Throwable) {
            false
        }

        private fun isExit(opcode: Int): Boolean = opcode in Opcodes.IRETURN..Opcodes.RETURN || opcode == Opcodes.ATHROW

        private fun fallsThrough(opcode: Int): Boolean =
            opcode != Opcodes.GOTO && !isExit(opcode)
    }

    /**
     * A [BasicInterpreter] that keeps **precise** reference and array-element
     * types (instead of collapsing everything to `Object`) and never loads
     * classes — differing types merge to `UNINITIALIZED_VALUE`, exactly what we
     * want to detect type conflicts without a classpath.
     */
    private class PreciseInterpreter : BasicInterpreter(Opcodes.ASM9) {
        override fun newValue(type: Type?): BasicValue? {
            if (type == null) return BasicValue.UNINITIALIZED_VALUE
            return when (type.sort) {
                Type.VOID -> null
                Type.OBJECT, Type.ARRAY -> BasicValue(type)
                else -> super.newValue(type)
            }
        }

        override fun binaryOperation(insn: AbstractInsnNode, value1: BasicValue, value2: BasicValue): BasicValue? {
            if (insn.opcode == Opcodes.AALOAD) {
                val arrayType = value1.type
                if (arrayType != null && arrayType.sort == Type.ARRAY) {
                    val element = Type.getType(arrayType.descriptor.substring(1))
                    return newValue(element)
                }
                return BasicValue.REFERENCE_VALUE
            }
            return super.binaryOperation(insn, value1, value2)
        }
    }

    private companion object {
        val NOT_FLATTENED = Outcome(false, 0)

        /** Minimum basic blocks worth flattening (dispatcher overhead vs. benefit). */
        const val MIN_BLOCKS = 3

        /** Minimum real instructions; tiny methods are skipped. */
        const val MIN_REAL_INSNS = 8

        /** Sentinel for the `null` stack-map type (assignable to any reference). */
        val NULL_VALUE: BasicValue = BasicValue(Type.getObjectType("null"))
    }
}
