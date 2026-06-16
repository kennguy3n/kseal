package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects a remote-access / screen-sharing tool controlling the device
 * ([RiskSignal.REMOTE_ACCESS]) — the typical "remote takeover" social-engineering
 * fraud vector.
 *
 * Wave-2 stub: registered but currently a no-op (returns no signals), so this
 * change is a behaviour-preserving reservation. The live check will read
 * [DeviceEnvironment.isAdbEnabled] and [DeviceEnvironment.installedPackages].
 */
internal class RemoteAccessDetector(
    @Suppress("unused") private val env: DeviceEnvironment,
) : Probe {

    override val id: String = "remote_access"

    override fun evaluate(): Set<RiskSignal> = emptySet()
}
