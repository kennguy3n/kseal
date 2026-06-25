package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects an attached debugger via the JDWP connection flag and the kernel
 * `TracerPid` (set when a native `ptrace`r — e.g. gdb/lldb — is attached).
 *
 * It also consults the native (Rust) tracer check via the trust-core C ABI
 * ([DeviceEnvironment.nativeDebuggerPresent]), which reads `TracerPid` from
 * below the JVM layer. The native result raises a signal only on an explicit
 * `== 1`; an unavailable check (negative) contributes nothing.
 */
internal class DebuggerDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "debugger"

    override fun evaluate(): Set<RiskSignal> {
        if (env.isDebuggerConnected()) return setOf(RiskSignal.DEBUGGER)
        val tracer = env.tracerPid()
        if (tracer > 0) return setOf(RiskSignal.DEBUGGER)
        return if (env.nativeDebuggerPresent() == 1) setOf(RiskSignal.DEBUGGER) else emptySet()
    }
}
