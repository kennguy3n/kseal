package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects an abusive accessibility service — a common input/UI-hijack vector
 * used to read on-screen content and inject taps/keystrokes
 * ([RiskSignal.ACCESSIBILITY_ABUSE]).
 *
 * Reads the enabled accessibility services from
 * [DeviceEnvironment.enabledAccessibilityServices] (flattened component names of
 * the form `package/.Service`) and flags when any enabled service's package is
 * neither a platform/OEM system namespace nor a well-known legitimate
 * accessibility suite.
 *
 * Matching is intentionally conservative because legitimate assistive-tech users
 * exist (screen readers, switch access, and some password managers rely on the
 * accessibility API), so this is a **fusion-weighted RISK signal, not an
 * auto-block**: the client only observes that a non-system service is enabled,
 * and the server's Score/Decision policy weighs the bit alongside the other
 * signals rather than the device denying access outright. The package-namespace
 * check is also spoofable by a sideloaded app, which is acceptable for the same
 * reason — repackaging/installer-source probes cover that vector and the signal
 * is fused, not trusted in isolation.
 */
internal class AccessibilityAbuseDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "accessibility"

    override fun evaluate(): Set<RiskSignal> {
        val hasThirdPartyService = env.enabledAccessibilityServices()
            .asSequence()
            .mapNotNull(::packageOf)
            .any { !isBenign(it) }

        return if (hasThirdPartyService) setOf(RiskSignal.ACCESSIBILITY_ABUSE) else emptySet()
    }

    /**
     * Extracts the package name from a flattened component name (`package/class`).
     * Falls back to the trimmed raw value when it carries no class separator so an
     * unexpected format is still classified rather than silently ignored; blank
     * entries are dropped.
     */
    private fun packageOf(componentName: String): String? {
        val pkg = componentName.trim().substringBefore('/').trim()
        return pkg.ifEmpty { null }
    }

    /** A package shipped as part of the platform/OEM or a known accessibility suite. */
    private fun isBenign(pkg: String): Boolean =
        pkg in BENIGN_PACKAGES || SYSTEM_PACKAGE_PREFIXES.any { pkg.startsWith(it) }

    private companion object {
        /**
         * Platform / major-OEM namespaces whose accessibility services are
         * first-party. Covering the large non-Pixel/Samsung OEMs (Huawei, Xiaomi,
         * OnePlus, Oppo/ColorOS, Vivo) keeps the bit from firing on their shipped
         * assistive services and skewing scoring calibration on those populations.
         * Prefix trust is spoofable by a sideloaded app, but that is acceptable
         * here for the same reason the rest of the check is — the signal is fused,
         * not trusted in isolation (see class doc).
         */
        val SYSTEM_PACKAGE_PREFIXES = listOf(
            "com.android.",
            "com.google.android.",
            "com.samsung.",
            "com.sec.android.",
            "com.huawei.",
            "com.xiaomi.",
            "com.miui.",
            "com.oneplus.",
            "com.oppo.",
            "com.coloros.",
            "com.vivo.",
        )

        /**
         * Well-known legitimate accessibility packages that fall outside the
         * system namespaces above. Kept deliberately small; everything else is
         * flagged so the server policy can weigh it.
         */
        val BENIGN_PACKAGES = hashSetOf(
            // The bare Android framework package (no namespace prefix to match).
            "android",
        )
    }
}
