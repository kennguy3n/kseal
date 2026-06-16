package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects the tapjacking / UI-redress pre-condition: another package holding the
 * "draw over other apps" permission (`SYSTEM_ALERT_WINDOW` /
 * `TYPE_APPLICATION_OVERLAY`) that could render a deceptive window on top of the
 * protected app ([RiskSignal.OVERLAY_ABUSE]).
 *
 * It enumerates [DeviceEnvironment.appsWithOverlayPermission] (which already
 * excludes the host app) and flags [RiskSignal.OVERLAY_ABUSE] when a holder is
 * *not* an OS-installed system app. Trust is established via
 * [DeviceEnvironment.isSystemPackage] — backed by `ApplicationInfo.FLAG_SYSTEM` /
 * `FLAG_UPDATED_SYSTEM_APP` — rather than by matching package-name prefixes.
 * That distinction matters: first-party surfaces (SystemUI, launchers, OEM
 * system overlays, the accessibility/IME framework) ship on the system partition
 * and so are reported as system apps, keeping the false-positive rate low, while
 * a user-installed app cannot evade detection merely by adopting a
 * system-looking package name (e.g. `com.samsung.android.<anything>`) — the flag
 * reflects the install partition, not the chosen name.
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

    /**
     * True when [pkg] is a non-system, third-party holder of the overlay
     * permission. Blank entries are ignored; everything that the OS does not
     * report as a system app is treated as the tapjacking pre-condition.
     */
    private fun isThirdPartyOverlay(pkg: String): Boolean {
        val name = pkg.trim()
        if (name.isEmpty()) return false
        return !env.isSystemPackage(name)
    }
}
