package io.kseal.sdk.probes

/**
 * Narrow seam over the raw OS/platform surface the probes inspect.
 *
 * Probes depend on this interface rather than Android/JVM APIs directly so they
 * stay deterministic and unit-testable on the JVM (a fake environment supplies
 * controlled inputs) while the production [AndroidDeviceEnvironment] reads the
 * real device. None of these methods perform network I/O.
 */
interface DeviceEnvironment {

    // --- Build identity (android.os.Build mirror) ---
    val fingerprint: String
    val model: String
    val manufacturer: String
    val brand: String
    val device: String
    val product: String
    val hardware: String
    val board: String
    val bootloader: String

    /** Space-separated `Build.TAGS` (e.g. "release-keys" or "test-keys"). */
    val buildTags: String

    /** Reads a system property (`android.os.SystemProperties`), or `null`. */
    fun systemProperty(key: String): String?

    // --- Filesystem ---
    fun fileExists(path: String): Boolean
    fun canExecute(path: String): Boolean

    /** Entries of a directory, or empty when it does not exist / is unreadable. */
    fun listDirectory(path: String): List<String>

    /** Reads a small text file fully, or `null` when missing/unreadable. */
    fun readText(path: String): String?

    /** Directories on `$PATH` to scan for binaries such as `su`. */
    fun pathDirectories(): List<String>

    // --- Process introspection ---
    /** `TracerPid` from `/proc/self/status`, or `-1` when unavailable. */
    fun tracerPid(): Int

    /** Whether a JDWP debugger is attached (`Debug.isDebuggerConnected()`). */
    fun isDebuggerConnected(): Boolean

    /** Lines of `/proc/self/maps`, or empty when unreadable. */
    fun processMaps(): List<String>

    /** Whether a TCP port is accepting connections on loopback (e.g. Frida 27042). */
    fun isLoopbackPortOpen(port: Int): Boolean

    // --- Package / signing ---
    fun installedPackages(): List<String>

    /** Installer package that delivered this app, or `null` when sideloaded. */
    fun installerPackageName(): String?

    /** SHA-256 (hex, lowercase) of each of this app's signing certificates. */
    fun signingCertificateSha256(): List<String>

    // --- Network posture ---
    /** Configured system HTTP proxy host, or `null`/empty when none. */
    fun httpProxyHost(): String?

    /** Number of user-installed (non-system) trusted CA certificates. */
    fun userInstalledCaCount(): Int

    // --- Fraud-vector surfaces (consumed by the Wave-2 RASP probes) ---
    /**
     * Component names of the currently enabled accessibility services
     * (`Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES`), or empty when none /
     * unreadable. An abusive accessibility service is a common input/UI-hijack
     * vector.
     */
    fun enabledAccessibilityServices(): List<String>

    /** IDs of the enabled input methods (keyboards), or empty when unreadable. */
    fun enabledInputMethodIds(): List<String>

    /** ID of the currently selected default input method, or `null`. */
    fun defaultInputMethodId(): String?

    /**
     * Packages (excluding this app) granted the "draw over other apps" overlay
     * permission (`SYSTEM_ALERT_WINDOW`) — the precondition for tapjacking — or
     * empty when none / unreadable.
     */
    fun appsWithOverlayPermission(): List<String>

    /** Whether ADB (`Settings.Global.ADB_ENABLED`) is enabled on the device. */
    fun isAdbEnabled(): Boolean
}
