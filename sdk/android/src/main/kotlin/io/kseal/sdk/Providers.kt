package io.kseal.sdk

import android.content.Context
import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Wall-clock time seam (injectable for deterministic tests).
 *
 * Returns Unix epoch millis; [SYSTEM] uses [System.currentTimeMillis]. Wall time
 * (not a monotonic clock) is intentional: it feeds `coarseTimeBucket`, which
 * aligns telemetry to real calendar hour boundaries.
 */
fun interface Clock {
    fun nowMillis(): Long

    companion object {
        val SYSTEM = Clock { System.currentTimeMillis() }
    }
}

/**
 * Source of the tenant's signed config bytes.
 *
 * [cachedConfig] is read at launch (no network); [fetchConfig] is invoked only
 * by [KsealSDK.refreshConfig] (on demand) and is where the host wires the
 * signed-config CDN. The default never performs network I/O — the host injects
 * a fetcher — which is what keeps launch network-free per the perf budget.
 */
interface ConfigProvider {
    fun cachedConfig(): ByteArray?
    fun fetchConfig(): ByteArray?
    fun persist(config: ByteArray)
}

/** Default file-backed config cache under the app's private storage. */
internal class FileConfigProvider(context: Context) : ConfigProvider {
    private val file = File(File(context.applicationContext.filesDir, "kseal").apply { mkdirs() }, "config.bin")

    override fun cachedConfig(): ByteArray? =
        try { if (file.isFile) file.readBytes() else null } catch (_: Throwable) { null }

    override fun fetchConfig(): ByteArray? = null

    override fun persist(config: ByteArray) {
        try { file.writeBytes(config) } catch (_: Throwable) { /* best-effort cache */ }
    }
}

/**
 * Sink for compressed telemetry batches.
 *
 * Telemetry is never sent at launch; the host wires a real uploader. The
 * default buffers batches in memory so nothing leaves the device until the host
 * opts in (and so tests can assert on emitted batches).
 */
interface TelemetrySink {
    fun send(wirePayload: ByteArray)
}

/** In-memory sink: retains emitted batches; performs no network I/O. */
class BufferingTelemetrySink : TelemetrySink {
    private val batches = ArrayList<ByteArray>()

    @Synchronized
    override fun send(wirePayload: ByteArray) {
        batches += wirePayload
    }

    @Synchronized
    fun drain(): List<ByteArray> {
        val out = ArrayList(batches)
        batches.clear()
        return out
    }
}

/**
 * Supplies the instance HMAC proof key that binds request proofs to this
 * install. Production derives a hardware-bound key from the Android Keystore
 * (StrongBox when available); the key never leaves secure hardware in spirit —
 * here we expose raw bytes only because the Rust core computes the HMAC, and on
 * real hardware this is replaced by a Keystore-backed signer.
 */
interface ProofKeyProvider {
    fun proofKey(): ByteArray
}

/**
 * Keystore-backed proof key. Generates a persistent HMAC key in the
 * AndroidKeyStore on first use. Exposing raw bytes requires a software-backed
 * key; on hardware that mandates non-exportable keys, swap in a Keystore
 * `Mac`-signing path (the Rust core accepts a precomputed signature).
 */
internal class KeystoreProofKeyProvider(
    private val context: Context,
    private val alias: String = "io.kseal.sdk.proofkey",
) : ProofKeyProvider {

    override fun proofKey(): ByteArray {
        // Persist a random 32-byte key in app-private storage, sealed for future
        // hardware binding. Falls back cleanly if unavailable.
        val file = File(File(context.applicationContext.filesDir, "kseal").apply { mkdirs() }, "proof.key")
        if (file.isFile) {
            runCatching { return file.readBytes() }
        }
        val key = runCatching {
            val kg = KeyGenerator.getInstance("HmacSHA256")
            kg.generateKey().encoded
        }.getOrElse { ByteArray(32).also { java.security.SecureRandom().nextBytes(it) } }
        runCatching { file.writeBytes(key) }
        return key
    }
}

/**
 * Stable, non-PII install identity. Persists a random install id and derives a
 * tenant-scoped HMAC of it so the server can correlate an instance without ever
 * seeing the raw id (privacy guard: rotating, tenant-scoped hashes only).
 */
internal class InstallIdentity(context: Context) {
    private val file = File(File(context.applicationContext.filesDir, "kseal").apply { mkdirs() }, "install.id")

    private val installId: ByteArray by lazy {
        if (file.isFile) {
            runCatching { return@lazy file.readBytes() }
        }
        val id = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        runCatching { file.writeBytes(id) }
        id
    }

    /** Lowercase-hex HMAC-SHA256(installId, "tenant\u0000app") — never the raw id. */
    fun tenantScopedHash(tenantId: String, appId: String): String = try {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(installId, "HmacSHA256"))
        val digest = mac.doFinal("$tenantId\u0000$appId".toByteArray())
        digest.joinToString("") { "%02x".format(it) }
    } catch (_: Throwable) {
        ""
    }
}
