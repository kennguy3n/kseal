package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects execution under an Android emulator using build-property heuristics,
 * QEMU markers, and emulator-only device nodes.
 */
internal class EmulatorDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "emulator"

    override fun evaluate(): Set<RiskSignal> =
        if (isEmulator()) setOf(RiskSignal.EMULATOR, RiskSignal.ENVIRONMENT) else emptySet()

    private fun isEmulator(): Boolean {
        if (env.systemProperty("ro.kernel.qemu") == "1") return true
        if (QEMU_NODES.any { env.fileExists(it) }) return true

        val fingerprint = env.fingerprint.lowercase()
        if (fingerprint.startsWith("generic") ||
            fingerprint.startsWith("unknown") ||
            fingerprint.contains("vbox") ||
            fingerprint.contains("emulator") ||
            fingerprint.contains("sdk_gphone") ||
            (fingerprint.contains("generic") && fingerprint.contains("test-keys"))
        ) {
            return true
        }

        val model = env.model.lowercase()
        if (MODEL_MARKERS.any { model.contains(it) }) return true

        val hardware = env.hardware.lowercase()
        if (HARDWARE_MARKERS.any { hardware.contains(it) }) return true

        val product = env.product.lowercase()
        if (PRODUCT_MARKERS.any { product.contains(it) }) return true

        if (env.manufacturer.contains("Genymotion", ignoreCase = true)) return true
        if (env.brand.startsWith("generic", ignoreCase = true) &&
            env.device.startsWith("generic", ignoreCase = true)
        ) {
            return true
        }
        if (env.board.lowercase() in setOf("goldfish", "ranchu", "unknown")) return true

        return false
    }

    private companion object {
        val QEMU_NODES = listOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/dev/goldfish_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
        )
        val MODEL_MARKERS = listOf(
            "google_sdk", "emulator", "android sdk built for", "sdk_gphone", "droid4x",
        )
        val HARDWARE_MARKERS = listOf("goldfish", "ranchu", "vbox86", "ttvm_x86", "android_x86")
        val PRODUCT_MARKERS = listOf(
            "sdk", "google_sdk", "sdk_x86", "sdk_gphone", "vbox86p", "emulator", "simulator",
        )
    }
}
