package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects network-interception posture: a configured system HTTP proxy and
 * user-installed CA certificates (the two most common MITM enablers). Pinning
 * failures are reported separately by the transport layer via
 * [io.kseal.sdk.KsealSDK.reportPinningFailure].
 */
internal class NetworkRiskDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "network"

    override fun evaluate(): Set<RiskSignal> {
        val signals = LinkedHashSet<RiskSignal>()

        if (!env.httpProxyHost().isNullOrBlank()) {
            signals += RiskSignal.PROXY
            signals += RiskSignal.NETWORK_MITM
        }
        if (env.userInstalledCaCount() > 0) {
            signals += RiskSignal.USER_CA
            signals += RiskSignal.NETWORK_MITM
        }
        return signals
    }
}
