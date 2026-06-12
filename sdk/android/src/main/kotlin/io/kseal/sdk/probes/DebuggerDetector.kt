package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects an attached debugger via the JDWP connection flag and the kernel
 * `TracerPid` (set when a native `ptrace`r — e.g. gdb/lldb — is attached).
 */
internal class DebuggerDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "debugger"

    override fun evaluate(): Set<RiskSignal> {
        if (env.isDebuggerConnected()) return setOf(RiskSignal.DEBUGGER)
        val tracer = env.tracerPid()
        return if (tracer > 0) setOf(RiskSignal.DEBUGGER) else emptySet()
    }
}
