package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects when the screen is being captured or recorded — a credential/OTP
 * exfiltration vector ([RiskSignal.SCREEN_CAPTURE]).
 *
 * Wave-2 stub: registered in the probe pipeline but currently a no-op (returns
 * no signals), so this change introduces zero runtime behaviour. Unlike the
 * other fraud-vector probes it reads no [DeviceEnvironment] accessor: live
 * capture is window/Activity-scoped (the `MediaProjection` lifecycle and the
 * screen-capture callbacks added in API 34), so the host wires it to the
 * foreground Activity in a follow-up rather than polling a global setting.
 */
internal class ScreenCaptureDetector : Probe {

    override val id: String = "screen_capture"

    override fun evaluate(): Set<RiskSignal> = emptySet()
}
