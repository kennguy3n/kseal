package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects an abusive accessibility service — a common input/UI-hijack vector
 * used to read screens and inject gestures ([RiskSignal.ACCESSIBILITY_ABUSE]).
 *
 * Wave-2 stub: registered but currently a no-op (returns no signals), so this
 * change is a behaviour-preserving reservation. The live check will read
 * [DeviceEnvironment.enabledAccessibilityServices].
 */
internal class AccessibilityAbuseDetector(
    @Suppress("unused") private val env: DeviceEnvironment,
) : Probe {

    override val id: String = "accessibility"

    override fun evaluate(): Set<RiskSignal> = emptySet()
}
