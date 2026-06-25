package io.kseal.gradle.internal

import java.io.File

/**
 * Verifies and records whether a shipped native library still carries the trust
 * core's sensitive string literals in plaintext.
 *
 * Phase 5.2 adds an opt-in, compile-time string-obfuscation tier to the Rust
 * trust core (the `obfuscate-strings` cargo feature; see
 * `sdk/rust-core/kseal-core/src/obfuscate.rs`). This inspector is the build-time
 * counterpart of [ElfInspector]: it does not transform the binary, it
 * **verifies** the posture and records it into the build-proof manifest so the
 * control plane has evidence of whether the hardened core was actually shipped.
 *
 * Detection is a pure, deterministic substring scan over the library bytes, so
 * it needs no toolchain, is fully unit-testable, and — being a function of the
 * already-hashed `.so` bytes — never perturbs the reproducible `build_hash`.
 *
 * The posture is only asserted for the kseal trust core itself, identified by
 * its exported C ABI symbol prefix (`kseal_`, which stays plaintext by design —
 * those names are linked by the JNI/Swift bridges). Third-party `.so`s we do not
 * build are reported as [Status.NOT_APPLICABLE] rather than falsely "clean".
 */
internal object NativeStringObfuscationInspector {

    /** Verification outcome recorded per library in the manifest. */
    enum class Status(val wire: String) {
        /** Trust core, and no sensitive plaintext sentinel was found. */
        OBFUSCATED("obfuscated"),

        /** Trust core, but at least one sentinel literal is present in plaintext. */
        PLAINTEXT("plaintext"),

        /** Not the kseal trust core (no `kseal_*` exports) — posture not asserted. */
        NOT_APPLICABLE("not-applicable"),

        /** The file could not be read. */
        INDETERMINATE("indeterminate"),
    }

    /** The string-obfuscation posture of a single `.so`. */
    data class Result(
        val status: Status,
        val isKsealCore: Boolean,
        /** Sentinels found in plaintext (empty unless [Status.PLAINTEXT]). */
        val markersFound: List<String>,
        val notes: List<String>,
    )

    /**
     * Sentinel literals the trust core obfuscates that do **not** appear in the
     * artifact from any other source. Their absence in a kseal core library is
     * strong evidence the hardened build was shipped. Short/ambiguous tokens
     * (e.g. `root`, `debugger`, `emulator`) are deliberately excluded — the
     * proto-generated reflection code emits those independently, so they are not
     * reliable obfuscation signals.
     */
    private val SENTINELS = listOf(
        "config signature verification failed",
        "network_mitm",
        "app_integrity",
    )

    /** Exported C ABI symbol prefix that identifies the kseal trust core. */
    private const val KSEAL_EXPORT_MARKER = "kseal_"

    fun inspect(file: File): Result {
        val bytes = runCatching { file.readBytes() }.getOrNull()
            ?: return Result(
                status = Status.INDETERMINATE,
                isKsealCore = false,
                markersFound = emptyList(),
                notes = listOf("native library could not be read"),
            )
        return inspectBytes(bytes)
    }

    /** Pure scanning core, exposed for unit tests. */
    fun inspectBytes(bytes: ByteArray): Result {
        if (!containsAscii(bytes, KSEAL_EXPORT_MARKER)) {
            return Result(
                status = Status.NOT_APPLICABLE,
                isKsealCore = false,
                markersFound = emptyList(),
                notes = listOf("no kseal_* exports; not the trust core, string posture not asserted"),
            )
        }
        val found = SENTINELS.filter { containsAscii(bytes, it) }
        return if (found.isEmpty()) {
            Result(Status.OBFUSCATED, isKsealCore = true, markersFound = emptyList(), notes = emptyList())
        } else {
            Result(
                status = Status.PLAINTEXT,
                isKsealCore = true,
                markersFound = found,
                notes = listOf(
                    "trust-core string literals present in plaintext; build the .so with the " +
                        "obfuscate-strings feature (KSEAL_OBFUSCATE_STRINGS=1) to harden them",
                ),
            )
        }
    }

    /** Deterministic ASCII substring search (the literals are pure ASCII). */
    private fun containsAscii(haystack: ByteArray, needle: String): Boolean {
        val n = needle.toByteArray(Charsets.US_ASCII)
        if (n.isEmpty() || n.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - n.size) {
            for (j in n.indices) {
                if (haystack[i + j] != n[j]) continue@outer
            }
            return true
        }
        return false
    }
}
