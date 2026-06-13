package io.kseal.gradle.internal

/**
 * Configurable strength of the bytecode control-flow obfuscation pass.
 *
 * The pass is **off by default** (the task is flag-gated); when enabled it
 * defaults to [LOW], which only encrypts string constants — the safest,
 * behaviour-neutral transform. Higher levels add opaque predicates to a growing
 * share of methods. No level performs VM/dispatcher virtualization, by design.
 */
internal enum class ObfuscationStrength {
    /** No transforms. */
    OFF,

    /** String-constant encryption only. Safe default when the pass is enabled. */
    LOW,

    /** String encryption + opaque predicates on a seed-chosen subset of methods. */
    MEDIUM,

    /** String encryption + opaque predicates on every eligible method. */
    HIGH,
    ;

    fun toOptions(keepStrings: Set<String>): BytecodeObfuscator.Options = when (this) {
        OFF -> BytecodeObfuscator.Options(
            encryptStrings = false, opaquePredicates = false, opaqueDensity = 0.0,
            minStringLength = Int.MAX_VALUE, keepStrings = keepStrings,
        )
        LOW -> BytecodeObfuscator.Options(
            encryptStrings = true, opaquePredicates = false, opaqueDensity = 0.0,
            minStringLength = 4, keepStrings = keepStrings,
        )
        MEDIUM -> BytecodeObfuscator.Options(
            encryptStrings = true, opaquePredicates = true, opaqueDensity = 0.35,
            minStringLength = 3, keepStrings = keepStrings,
        )
        HIGH -> BytecodeObfuscator.Options(
            encryptStrings = true, opaquePredicates = true, opaqueDensity = 1.0,
            minStringLength = 2, keepStrings = keepStrings,
        )
    }

    companion object {
        /** Parses a case-insensitive DSL value, falling back to [LOW] for unknown input. */
        fun parse(value: String?): ObfuscationStrength =
            values().firstOrNull { it.name.equals(value?.trim(), ignoreCase = true) } ?: LOW
    }
}
