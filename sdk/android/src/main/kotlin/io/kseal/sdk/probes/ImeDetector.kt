package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects a malicious or untrusted input method (keyboard) capable of
 * keylogging credentials ([RiskSignal.MALICIOUS_IME]).
 *
 * Wave-2 stub: registered but currently a no-op (returns no signals), so this
 * change is a behaviour-preserving reservation. The live check will read
 * [DeviceEnvironment.enabledInputMethodIds] and
 * [DeviceEnvironment.defaultInputMethodId].
 */
internal class ImeDetector(
    @Suppress("unused") private val env: DeviceEnvironment,
) : Probe {

    override val id: String = "ime"

    override fun evaluate(): Set<RiskSignal> = emptySet()
}
