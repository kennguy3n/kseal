package io.kseal.gradle.internal

/**
 * Configurable strength of the bytecode control-flow obfuscation pass.
 *
 * The pass is **off by default** (the task is flag-gated); when enabled it
 * defaults to [LOW], which only encrypts string constants — the safest,
 * behaviour-neutral transform. Higher levels add opaque predicates to a growing
 * share of methods; [HIGH] additionally enables MBA substitution and
 * dispatcher-based control-flow flattening. No level performs VM/dispatcher
 * virtualization, by design.
 */
internal enum class ObfuscationStrength {
    /** No transforms. */
    OFF,

    /** String-constant encryption only. Safe default when the pass is enabled. */
    LOW,

    /** String encryption + opaque predicates on a seed-chosen subset of methods. */
    MEDIUM,

    /**
     * String encryption + opaque predicates on every eligible method, plus MBA
     * substitution and dispatcher-based control-flow flattening (both honouring
     * [KeepRules] and falling back to the original method on any analysis doubt).
     */
    HIGH,
    ;

    fun toOptions(
        keepStrings: Set<String>,
        keepRules: KeepRules? = null,
    ): BytecodeObfuscator.Options = when (this) {
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
            mixedBooleanArithmetic = true, flattenControlFlow = true,
            keepRules = keepRules,
        )
    }

    companion object {
        /** Comma-separated list of the accepted DSL values, for error messages. */
        val accepted: String
            get() = values().joinToString(", ") { it.name.lowercase() }

        /**
         * Parses a case-insensitive, whitespace-tolerant DSL value.
         *
         * Throws [IllegalArgumentException] with the list of valid values on
         * unrecognized input rather than silently downgrading to a weaker level —
         * a typo'd `strength` must fail loudly, never quietly reduce protection.
         */
        fun parseStrict(value: String?): ObfuscationStrength {
            val normalized = value?.trim()
            return values().firstOrNull { it.name.equals(normalized, ignoreCase = true) }
                ?: throw IllegalArgumentException(
                    "unknown obfuscation strength '${value.orEmpty()}'. Valid values are: $accepted.",
                )
        }
    }
}
