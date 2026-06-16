package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects tapjacking / UI-redress overlays: another package holding the "draw
 * over other apps" permission drawing on top of the protected app
 * ([RiskSignal.OVERLAY_ABUSE]).
 *
 * Wave-2 stub: registered but currently a no-op (returns no signals), so this
 * change is a behaviour-preserving reservation. The live check will read
 * [DeviceEnvironment.appsWithOverlayPermission].
 */
internal class OverlayDetector(
    @Suppress("unused") private val env: DeviceEnvironment,
) : Probe {

    override val id: String = "overlay"

    override fun evaluate(): Set<RiskSignal> = emptySet()
}
