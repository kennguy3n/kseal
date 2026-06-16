package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects a remote-access / screen-sharing tool able to control the device
 * ([RiskSignal.REMOTE_ACCESS]) — the classic "remote takeover" social-engineering
 * fraud vector, where a victim is talked into installing remote-control software
 * (or enabling ADB) so an attacker can drive the device during a session.
 *
 * The check is intentionally conservative and fuses two independent signals,
 * either of which is sufficient to flag [RiskSignal.REMOTE_ACCESS]:
 *  - **ADB enabled** ([DeviceEnvironment.isAdbEnabled]). Developer ADB — and
 *    especially ADB-over-TCP/IP — is a direct remote-control channel.
 *  - **A known remote-control / screen-share app is installed**
 *    ([DeviceEnvironment.installedPackages] matched against
 *    [REMOTE_CONTROL_PACKAGE_TOKENS] as case-insensitive substrings, so the
 *    host/support/client package variants vendors ship are all covered).
 *
 * Active screen mirroring / projection is not portably queryable from this
 * seam; the related "the screen is being recorded" surface is reported
 * separately by [ScreenCaptureDetector].
 */
internal class RemoteAccessDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "remote_access"

    override fun evaluate(): Set<RiskSignal> {
        val signals = LinkedHashSet<RiskSignal>()
        if (env.isAdbEnabled() || hasRemoteControlApp()) {
            signals += RiskSignal.REMOTE_ACCESS
        }
        return signals
    }

    private fun hasRemoteControlApp(): Boolean =
        env.installedPackages().any { pkg ->
            val lower = pkg.lowercase()
            REMOTE_CONTROL_PACKAGE_TOKENS.any { token -> lower.contains(token) }
        }

    private companion object {
        /**
         * Lowercase package-name substrings of well-known remote-control /
         * screen-share tooling abused for remote takeover. These are matched as
         * substrings (not exact ids) so vendor host/support/client package
         * variants — e.g. TeamViewer's QuickSupport and Host packages — are all
         * covered by a single token.
         */
        val REMOTE_CONTROL_PACKAGE_TOKENS = listOf(
            "com.teamviewer",                  // TeamViewer (+ QuickSupport / Host)
            "com.anydesk",                     // AnyDesk
            "com.carriez.flutter_hbb",         // RustDesk
            "com.sand.airdroid",               // AirDroid
            "com.sand.airmirror",              // AirMirror (AirDroid remote control)
            "com.splashtop",                   // Splashtop
            "com.google.chromeremotedesktop",  // Chrome Remote Desktop
            "com.rsupport",                    // RSUPPORT RemoteCall / Mobizen Mirroring
            "com.zoho.assist",                 // Zoho Assist
            "com.aweray.remote",               // AweSun / AweRay Remote
            "com.alpemix",                     // Alpemix
            "com.bomgar",                      // BeyondTrust Remote Support (Bomgar)
            "com.islonline",                   // ISL Light
        )
    }
}
