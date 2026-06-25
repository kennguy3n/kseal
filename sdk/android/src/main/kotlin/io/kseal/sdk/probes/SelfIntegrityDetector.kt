package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Runtime self-integrity baseline supplied by the protected build / signed
 * config: the expected SHA-256 of code and packaged-resource files measured at
 * build time.
 *
 * When a map is empty the corresponding check is skipped — the SDK never
 * fabricates a baseline, so an unconfigured check contributes no signal and
 * cannot cause a false positive. Each entry maps an absolute on-device file
 * path to its expected lowercase-hex SHA-256.
 *
 * @property expectedCodeSha256 code/library files (e.g. native `.so` images);
 *   a successfully measured digest that differs raises [RiskSignal.TAMPER]
 *   ("in-memory code/section checksum mismatch").
 * @property expectedArtifactSha256 packaged artifacts/resources; a successfully
 *   measured digest that differs raises [RiskSignal.APP_INTEGRITY]
 *   ("packaged artifact/resource digest mismatch").
 * @property failClosedOnUnmeasurable opt-in for high-security deployments. When
 *   `false` (default) a baseline-registered file whose digest cannot be measured
 *   is skipped (fail-safe, no signal). When `true` an unmeasurable
 *   baseline-registered file is treated as a mismatch — it raises
 *   [RiskSignal.TAMPER] for [expectedCodeSha256] and [RiskSignal.APP_INTEGRITY]
 *   for [expectedArtifactSha256] — so an attacker cannot evade the check by
 *   making a registered file unreadable. Only affects paths that have a
 *   baseline; an empty map is still fully silent.
 */
data class TamperPolicy(
    val expectedCodeSha256: Map<String, String> = emptyMap(),
    val expectedArtifactSha256: Map<String, String> = emptyMap(),
    val failClosedOnUnmeasurable: Boolean = false,
)

/**
 * In-process runtime self-integrity loop: re-checksums the app's code and
 * packaged resources on every trust evaluation and compares each against the
 * build-time baseline in [TamperPolicy].
 *
 * Fail-safe by construction:
 * - an empty baseline map skips that check entirely (no baseline → no signal);
 * - a file whose digest cannot be measured ([DeviceEnvironment.sha256OfFile]
 *   returns `null`) contributes nothing — only a *successfully measured* digest
 *   that differs from the baseline raises a signal. A deployment can opt into
 *   fail-closed handling of unmeasurable files via
 *   [TamperPolicy.failClosedOnUnmeasurable].
 *
 * Raises [RiskSignal.TAMPER] for code mismatches and [RiskSignal.APP_INTEGRITY]
 * for packaged-artifact mismatches. The SDK only raises signals; it never
 * auto-enforces.
 */
internal class SelfIntegrityDetector(
    private val env: DeviceEnvironment,
    private val policy: TamperPolicy,
) : Probe {

    override val id: String = "selfIntegrity"

    override fun evaluate(): Set<RiskSignal> {
        val signals = LinkedHashSet<RiskSignal>()

        if (mismatchExists(policy.expectedCodeSha256)) {
            signals += RiskSignal.TAMPER
        }
        if (mismatchExists(policy.expectedArtifactSha256)) {
            signals += RiskSignal.APP_INTEGRITY
        }

        return signals
    }

    /**
     * Returns true when at least one file in [expected] mismatches its baseline.
     * An unmeasurable file is skipped by default, or treated as a mismatch when
     * [TamperPolicy.failClosedOnUnmeasurable] is set.
     */
    private fun mismatchExists(expected: Map<String, String>): Boolean {
        if (expected.isEmpty()) return false
        for ((path, baseline) in expected) {
            val actual = env.sha256OfFile(path)
            if (actual == null) {
                if (policy.failClosedOnUnmeasurable) return true
                continue
            }
            if (!actual.equals(baseline, ignoreCase = true)) {
                return true
            }
        }
        return false
    }
}
