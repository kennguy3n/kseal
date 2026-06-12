package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects dynamic-instrumentation frameworks: Frida (mapped libraries, gadget,
 * default control port 27042), Xposed/EdXposed/LSPosed, and Substrate, by
 * scanning `/proc/self/maps`, loaded packages, and on-disk agent artifacts.
 */
internal class HookDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "hook"

    override fun evaluate(): Set<RiskSignal> =
        if (mapsContainHooks() || hasFridaArtifacts() || fridaPortOpen() || hasHookPackage()) {
            setOf(RiskSignal.HOOKING)
        } else {
            emptySet()
        }

    private fun mapsContainHooks(): Boolean {
        val maps = env.processMaps()
        if (maps.isEmpty()) return false
        return maps.any { line ->
            val lower = line.lowercase()
            MAP_MARKERS.any { lower.contains(it) }
        }
    }

    private fun hasFridaArtifacts(): Boolean = FRIDA_ARTIFACTS.any { env.fileExists(it) }

    private fun fridaPortOpen(): Boolean =
        env.isLoopbackPortOpen(FRIDA_DEFAULT_PORT) || env.isLoopbackPortOpen(FRIDA_ALT_PORT)

    private fun hasHookPackage(): Boolean {
        val installed = env.installedPackages().toHashSet()
        return HOOK_PACKAGES.any { it in installed }
    }

    private companion object {
        const val FRIDA_DEFAULT_PORT = 27042
        const val FRIDA_ALT_PORT = 27043

        val MAP_MARKERS = listOf(
            "frida", "frida-agent", "frida-gadget", "gum-js-loop", "gmain", "libfrida",
            "xposed", "libxposed", "substrate", "libsubstrate", "epic.bridge",
        )

        val FRIDA_ARTIFACTS = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-gadget.so",
        )

        val HOOK_PACKAGES = listOf(
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager",
            "io.va.exposed",
            "com.saurik.substrate",
        )
    }
}
