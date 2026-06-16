package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects the tapjacking / UI-redress pre-condition: another package holding the
 * "draw over other apps" permission (`SYSTEM_ALERT_WINDOW` /
 * `TYPE_APPLICATION_OVERLAY`) that could render a deceptive window on top of the
 * protected app ([RiskSignal.OVERLAY_ABUSE]).
 *
 * It enumerates [DeviceEnvironment.appsWithOverlayPermission] (which already
 * excludes the host app) and flags [RiskSignal.OVERLAY_ABUSE] when a package
 * that is *not* a known system / launcher / accessibility-framework component
 * holds the permission. Those first-party surfaces (SystemUI, launchers, OEM
 * system overlays, the accessibility/IME framework) routinely and legitimately
 * hold `SYSTEM_ALERT_WINDOW`, so they are excluded to keep the false-positive
 * rate low; the check is intentionally conservative and treats only third-party
 * packages outside those namespaces as the abuse pre-condition.
 *
 * This is a fusion-weighted risk signal, not an auto-block: the server combines
 * it with other signals before deciding. The definitive per-touch confirmation
 * is `MotionEvent.FLAG_WINDOW_IS_OBSCURED`, but that is touch-event-scoped and
 * therefore out of scope for this probe-time check.
 */
internal class OverlayDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "overlay"

    override fun evaluate(): Set<RiskSignal> {
        val abusive = env.appsWithOverlayPermission().any(::isThirdPartyOverlay)
        return if (abusive) setOf(RiskSignal.OVERLAY_ABUSE) else emptySet()
    }

    /** True when [pkg] is a non-system, third-party holder of the overlay permission. */
    private fun isThirdPartyOverlay(pkg: String): Boolean {
        val name = pkg.trim()
        if (name.isEmpty()) return false
        if (name in SYSTEM_PACKAGES) return false
        return SYSTEM_PREFIXES.none { name.startsWith(it) }
    }

    private companion object {
        /** Exact first-party packages that routinely hold `SYSTEM_ALERT_WINDOW`. */
        val SYSTEM_PACKAGES = setOf(
            "android",
        )

        /**
         * Package-name prefixes for first-party / OEM system, launcher, and
         * accessibility-framework components that legitimately draw overlays.
         * Conservative by design: a package outside every one of these
         * namespaces that still holds the overlay permission is treated as the
         * tapjacking pre-condition.
         */
        val SYSTEM_PREFIXES = listOf(
            "io.kseal.",            // our own SDK / host namespace (defensive)
            "android.",
            "com.android.",         // AOSP: systemui, launcher, settings, ...
            "com.google.android.",  // GMS, SystemUI, Pixel launcher, TalkBack, ...
            "com.samsung.android.", // Samsung One UI system surfaces
            "com.sec.android.",     // Samsung legacy system surfaces
            "com.miui.",            // Xiaomi MIUI system UI
            "com.xiaomi.",
            "com.huawei.",
            "com.hihonor.",
            "com.oppo.",
            "com.coloros.",
            "com.oneplus.",
            "com.realme.",
            "com.vivo.",
            "com.bbk.",
            "com.lge.",
            "com.sonymobile.",
            "com.motorola.",
            "com.asus.",            // ASUS / ROG
            "com.nothing.",         // Nothing
            "com.transsion.",       // Transsion (Tecno / Infinix / itel)
            "com.tecno.",
            "com.infinix.",
            "com.zte.",
            "com.lenovo.",
        )
    }
}
