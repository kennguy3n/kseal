package io.kseal.sdk.probes

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.view.inputmethod.InputMethodManager
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest

/**
 * Production [DeviceEnvironment] reading the real Android device.
 *
 * All probes use raw OS APIs that cannot be portably implemented in the Rust
 * core (`/proc`, signing info, the CA store), which is exactly why they live in
 * the platform SDK. Every accessor is defensive: a failure degrades to a
 * "nothing observed" result rather than throwing.
 */
internal class AndroidDeviceEnvironment(context: Context) : DeviceEnvironment {

    private val appContext: Context = context.applicationContext
    private val packageName: String = appContext.packageName

    override val fingerprint: String get() = Build.FINGERPRINT.orEmpty()
    override val model: String get() = Build.MODEL.orEmpty()
    override val manufacturer: String get() = Build.MANUFACTURER.orEmpty()
    override val brand: String get() = Build.BRAND.orEmpty()
    override val device: String get() = Build.DEVICE.orEmpty()
    override val product: String get() = Build.PRODUCT.orEmpty()
    override val hardware: String get() = Build.HARDWARE.orEmpty()
    override val board: String get() = Build.BOARD.orEmpty()
    override val bootloader: String get() = Build.BOOTLOADER.orEmpty()
    override val buildTags: String get() = Build.TAGS.orEmpty()

    override fun systemProperty(key: String): String? = try {
        @Suppress("PrivateApi")
        val clazz = Class.forName("android.os.SystemProperties")
        val getter = clazz.getMethod("get", String::class.java)
        (getter.invoke(null, key) as? String)?.takeIf { it.isNotEmpty() }
    } catch (_: Throwable) {
        null
    }

    override fun fileExists(path: String): Boolean = try {
        File(path).exists()
    } catch (_: Throwable) {
        false
    }

    override fun canExecute(path: String): Boolean = try {
        File(path).let { it.exists() && it.canExecute() }
    } catch (_: Throwable) {
        false
    }

    override fun listDirectory(path: String): List<String> = try {
        File(path).listFiles()?.map { it.name } ?: emptyList()
    } catch (_: Throwable) {
        emptyList()
    }

    override fun readText(path: String): String? = try {
        val f = File(path)
        if (f.isFile && f.canRead()) f.readText() else null
    } catch (_: Throwable) {
        null
    }

    override fun pathDirectories(): List<String> =
        (System.getenv("PATH") ?: "").split(':').filter { it.isNotBlank() }

    override fun tracerPid(): Int {
        val status = readText("/proc/self/status") ?: return -1
        for (line in status.lineSequence()) {
            if (line.startsWith("TracerPid:")) {
                return line.substringAfter(':').trim().toIntOrNull() ?: -1
            }
        }
        return -1
    }

    override fun isDebuggerConnected(): Boolean = try {
        Debug.isDebuggerConnected()
    } catch (_: Throwable) {
        false
    }

    override fun processMaps(): List<String> =
        readText("/proc/self/maps")?.lines() ?: emptyList()

    override fun isLoopbackPortOpen(port: Int): Boolean = try {
        Socket().use { s ->
            s.connect(InetSocketAddress("127.0.0.1", port), CONNECT_TIMEOUT_MS)
            true
        }
    } catch (_: Throwable) {
        false
    }

    override fun installedPackages(): List<String> = try {
        val pm = appContext.packageManager
        pm.getInstalledPackages(0).map { it.packageName }
    } catch (_: Throwable) {
        emptyList()
    }

    override fun installerPackageName(): String? = try {
        val pm = appContext.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    } catch (_: Throwable) {
        null
    }

    @Suppress("DEPRECATION", "PackageManagerGetSignatures")
    override fun signingCertificateSha256(): List<String> = try {
        val pm = appContext.packageManager
        val md = MessageDigest.getInstance("SHA-256")
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val signing = info.signingInfo
            when {
                signing == null -> emptyArray()
                signing.hasMultipleSigners() -> signing.apkContentsSigners
                else -> signing.signingCertificateHistory
            }
        } else {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures ?: emptyArray()
        }
        signatures.map { sig -> md.digest(sig.toByteArray()).toHex() }
    } catch (_: Throwable) {
        emptyList()
    }

    override fun httpProxyHost(): String? {
        val host = System.getProperty("http.proxyHost")?.takeIf { it.isNotBlank() }
        if (host != null) return host
        return System.getProperty("https.proxyHost")?.takeIf { it.isNotBlank() }
    }

    override fun userInstalledCaCount(): Int = try {
        // The "AndroidCAStore" exposes both system and user anchors; user-added
        // anchors carry a "user:" alias prefix.
        val ks = KeyStore.getInstance("AndroidCAStore")
        ks.load(null, null)
        var count = 0
        val aliases = ks.aliases()
        while (aliases.hasMoreElements()) {
            if (aliases.nextElement().startsWith("user:")) count++
        }
        count
    } catch (_: Throwable) {
        0
    }

    override fun enabledAccessibilityServices(): List<String> = try {
        val raw = Settings.Secure.getString(
            appContext.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        )
        raw?.split(':')?.filter { it.isNotBlank() } ?: emptyList()
    } catch (_: Throwable) {
        emptyList()
    }

    override fun enabledInputMethodIds(): List<String> = try {
        val imm = appContext.getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
        imm?.enabledInputMethodList?.mapNotNull { it.id } ?: emptyList()
    } catch (_: Throwable) {
        emptyList()
    }

    override fun defaultInputMethodId(): String? = try {
        Settings.Secure.getString(
            appContext.contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
        )?.takeIf { it.isNotBlank() }
    } catch (_: Throwable) {
        null
    }

    override fun appsWithOverlayPermission(): List<String> = try {
        val pm = appContext.packageManager
        pm.getPackagesHoldingPermissions(arrayOf(Manifest.permission.SYSTEM_ALERT_WINDOW), 0)
            .mapNotNull { it.packageName }
            .filter { it != packageName }
    } catch (_: Throwable) {
        emptyList()
    }

    override fun isSystemPackage(packageName: String): Boolean = try {
        val pm = appContext.packageManager
        val flags = pm.getApplicationInfo(packageName, 0).flags
        (flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
    } catch (_: Throwable) {
        false
    }

    override fun isAdbEnabled(): Boolean = try {
        Settings.Global.getInt(appContext.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    } catch (_: Throwable) {
        false
    }

    private fun ByteArray.toHex(): String {
        val sb = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xFF
            sb.append(HEX[v ushr 4])
            sb.append(HEX[v and 0x0F])
        }
        return sb.toString()
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 120
        val HEX = "0123456789abcdef".toCharArray()
    }
}
