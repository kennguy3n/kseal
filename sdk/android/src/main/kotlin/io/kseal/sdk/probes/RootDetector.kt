package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal

/**
 * Detects rooting / privilege-escalation: `su` binaries, Magisk artifacts,
 * known root-management packages, permissive SELinux, and test-keys builds.
 */
internal class RootDetector(private val env: DeviceEnvironment) : Probe {

    override val id: String = "root"

    override fun evaluate(): Set<RiskSignal> {
        val signals = LinkedHashSet<RiskSignal>()

        if (hasSuBinary() || hasMagiskArtifacts() || hasRootPackage()) {
            signals += RiskSignal.ROOT
        }
        if (isSelinuxPermissive() || hasTestKeys() || isDebuggableBuild()) {
            signals += RiskSignal.ENVIRONMENT
        }
        return signals
    }

    private fun hasSuBinary(): Boolean {
        if (SU_PATHS.any { env.canExecute(it) || env.fileExists(it) }) return true
        return env.pathDirectories().any { dir -> env.canExecute("$dir/su") }
    }

    private fun hasMagiskArtifacts(): Boolean =
        MAGISK_PATHS.any { env.fileExists(it) }

    private fun hasRootPackage(): Boolean {
        val installed = env.installedPackages().toHashSet()
        return ROOT_PACKAGES.any { it in installed }
    }

    private fun isSelinuxPermissive(): Boolean {
        // 0 = permissive in the kernel sysfs node.
        val enforce = env.readText("/sys/fs/selinux/enforce")?.trim()
        if (enforce == "0") return true
        val prop = env.systemProperty("ro.boot.selinux")?.lowercase()
        return prop == "permissive" || prop == "disabled"
    }

    private fun hasTestKeys(): Boolean = env.buildTags.contains("test-keys")

    private fun isDebuggableBuild(): Boolean =
        env.systemProperty("ro.debuggable") == "1" || env.systemProperty("ro.secure") == "0"

    private companion object {
        val SU_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su",
            "/cache/su",
            "/dev/su",
        )

        val MAGISK_PATHS = listOf(
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/init.magisk.rc",
            "/sbin/magisk",
            "/system/bin/magisk",
        )

        val ROOT_PACKAGES = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
        )
    }
}
