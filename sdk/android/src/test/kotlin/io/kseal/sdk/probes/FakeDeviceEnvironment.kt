package io.kseal.sdk.probes

/**
 * Controllable [DeviceEnvironment] for deterministic probe unit tests. Every
 * field defaults to a benign, "clean device" value; tests override only what
 * the probe under test inspects.
 */
internal class FakeDeviceEnvironment(
    override var fingerprint: String = "google/sunfish/sunfish:13/TQ3A.230805.001/release-keys",
    override var model: String = "Pixel 4a",
    override var manufacturer: String = "Google",
    override var brand: String = "google",
    override var device: String = "sunfish",
    override var product: String = "sunfish",
    override var hardware: String = "sunfish",
    override var board: String = "sunfish",
    override var bootloader: String = "s5-0.4-9000000",
    override var buildTags: String = "release-keys",
) : DeviceEnvironment {

    val systemProperties: MutableMap<String, String> = HashMap()
    val existingFiles: MutableSet<String> = HashSet()
    val executableFiles: MutableSet<String> = HashSet()
    val directories: MutableMap<String, List<String>> = HashMap()
    val textFiles: MutableMap<String, String> = HashMap()
    var pathDirs: List<String> = listOf("/system/bin", "/system/xbin", "/vendor/bin")
    var tracerPid: Int = 0
    var debuggerConnected: Boolean = false
    var maps: List<String> = emptyList()
    val openPorts: MutableSet<Int> = HashSet()
    var packages: List<String> = listOf("com.android.vending", "com.example.host")
    var installer: String? = "com.android.vending"
    var signingCerts: List<String> = listOf("aa".repeat(32))
    var proxyHost: String? = null
    var userCaCount: Int = 0
    var accessibilityServices: List<String> = emptyList()
    var inputMethodIds: List<String> = listOf("com.google.android.inputmethod.latin/.LatinIME")
    var defaultInputMethod: String? = "com.google.android.inputmethod.latin/.LatinIME"
    var overlayPackages: List<String> = emptyList()
    var adbEnabled: Boolean = false

    override fun systemProperty(key: String): String? = systemProperties[key]
    override fun fileExists(path: String): Boolean = path in existingFiles || path in executableFiles
    override fun canExecute(path: String): Boolean = path in executableFiles
    override fun listDirectory(path: String): List<String> = directories[path] ?: emptyList()
    override fun readText(path: String): String? = textFiles[path]
    override fun pathDirectories(): List<String> = pathDirs
    override fun tracerPid(): Int = tracerPid
    override fun isDebuggerConnected(): Boolean = debuggerConnected
    override fun processMaps(): List<String> = maps
    override fun isLoopbackPortOpen(port: Int): Boolean = port in openPorts
    override fun installedPackages(): List<String> = packages
    override fun installerPackageName(): String? = installer
    override fun signingCertificateSha256(): List<String> = signingCerts
    override fun httpProxyHost(): String? = proxyHost
    override fun userInstalledCaCount(): Int = userCaCount
    override fun enabledAccessibilityServices(): List<String> = accessibilityServices
    override fun enabledInputMethodIds(): List<String> = inputMethodIds
    override fun defaultInputMethodId(): String? = defaultInputMethod
    override fun appsWithOverlayPermission(): List<String> = overlayPackages
    override fun isAdbEnabled(): Boolean = adbEnabled
}
