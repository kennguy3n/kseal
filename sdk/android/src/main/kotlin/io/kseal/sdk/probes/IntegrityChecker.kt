package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Expected-integrity baseline supplied by the protected build / signed config.
 *
 * When a field is empty the corresponding check is skipped (the SDK never
 * fabricates a baseline — an unconfigured check simply does not contribute a
 * signal, so it cannot cause false positives).
 *
 * @property expectedSigningCertSha256 lowercase-hex SHA-256 of the legitimate signing certificate(s).
 * @property allowedInstallers installer package names considered trusted (e.g. the Play Store).
 * @property requireKnownInstaller when true, a sideloaded / unknown installer raises an integrity signal.
 */
data class IntegrityPolicy(
    val expectedSigningCertSha256: Set<String> = emptySet(),
    val allowedInstallers: Set<String> = DEFAULT_ALLOWED_INSTALLERS,
    val requireKnownInstaller: Boolean = false,
) {
    companion object {
        val DEFAULT_ALLOWED_INSTALLERS: Set<String> = setOf(
            "com.android.vending",
            "com.google.android.feedback",
        )
    }
}

/**
 * Verifies app integrity: signing-certificate match (repackage/resign
 * detection) and installer provenance.
 */
internal class IntegrityChecker(
    private val env: DeviceEnvironment,
    private val policy: IntegrityPolicy,
) : Probe {

    override val id: String = "integrity"

    override fun evaluate(): Set<RiskSignal> {
        val signals = LinkedHashSet<RiskSignal>()

        if (policy.expectedSigningCertSha256.isNotEmpty()) {
            val actual = env.signingCertificateSha256().map { it.lowercase() }.toHashSet()
            val expected = policy.expectedSigningCertSha256.map { it.lowercase() }.toHashSet()
            // A repackaged/resigned APK presents a signing cert outside the baseline.
            val matches = actual.isNotEmpty() && actual.any { it in expected }
            if (!matches) {
                signals += RiskSignal.REPACKAGED
                signals += RiskSignal.APP_INTEGRITY
            }
        }

        if (policy.requireKnownInstaller) {
            val installer = env.installerPackageName()
            if (installer == null || installer !in policy.allowedInstallers) {
                signals += RiskSignal.APP_INTEGRITY
            }
        }

        return signals
    }
}
