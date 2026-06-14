package io.kseal.sdk

import android.content.Context
import io.kseal.sdk.internal.NativeTrustCore
import io.kseal.sdk.internal.TrustCore
import io.kseal.sdk.probes.AndroidDeviceEnvironment
import io.kseal.sdk.probes.DebuggerDetector
import io.kseal.sdk.probes.DeviceEnvironment
import io.kseal.sdk.probes.EmulatorDetector
import io.kseal.sdk.probes.HookDetector
import io.kseal.sdk.probes.IntegrityChecker
import io.kseal.sdk.probes.IntegrityPolicy
import io.kseal.sdk.probes.NetworkRiskDetector
import io.kseal.sdk.probes.Probe
import io.kseal.sdk.probes.RootDetector
import java.util.concurrent.atomic.AtomicLong

/**
 * Optional initialization knobs. Defaults keep launch network-free and the
 * footprint small; the host overrides only what it needs.
 *
 * @property configPublicKey Ed25519 public key (32 bytes) used to verify signed configs.
 * @property buildHash content hash of the protected build (from the Gradle hardening plugin).
 * @property integrityPolicy expected signing certs / installers for the integrity probe.
 * @property enabledProbes the probe ids to run; null runs all (tenants include only what they need).
 * @property maxBatchEvents telemetry events buffered before a batch is flushed.
 */
data class KsealOptions(
    val configPublicKey: ByteArray = ByteArray(32),
    val buildHash: String = "",
    val integrityPolicy: IntegrityPolicy = IntegrityPolicy(),
    val enabledProbes: Set<String>? = null,
    val maxBatchEvents: Int = 32,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KsealOptions) return false
        return configPublicKey.contentEquals(other.configPublicKey) &&
            buildHash == other.buildHash &&
            integrityPolicy == other.integrityPolicy &&
            enabledProbes == other.enabledProbes &&
            maxBatchEvents == other.maxBatchEvents
    }

    override fun hashCode(): Int {
        var result = configPublicKey.contentHashCode()
        result = 31 * result + buildHash.hashCode()
        result = 31 * result + integrityPolicy.hashCode()
        result = 31 * result + (enabledProbes?.hashCode() ?: 0)
        result = 31 * result + maxBatchEvents
        return result
    }
}

/**
 * Public entry point to the kseal device SDK.
 *
 * Wraps the shared Rust trust core (over JNI) and the native Android RASP
 * probes. The SDK gathers signals, hands the packed risk bitset to the core for
 * scoring, and produces per-request proofs — but never makes the final trust
 * decision (the server does). It performs **no network I/O at launch**: probes
 * run lazily on demand and telemetry is batched.
 *
 * Typical use:
 * ```
 * val sdk = KsealSDK.initialize(context, tenantId, appId, apiKey)
 * val risk = sdk.evaluateRisk()
 * val proof = sdk.getRequestProof(requestHash)
 * ```
 */
class KsealSDK internal constructor(
    private val tenantId: String,
    private val appId: String,
    @Suppress("unused") private val apiKey: String,
    private val core: TrustCore,
    private val env: DeviceEnvironment,
    private val options: KsealOptions,
    private val configProvider: ConfigProvider,
    private val telemetrySink: TelemetrySink,
    private val installIdentityHash: String,
    private val clock: Clock,
) {

    private val probes: List<Probe> = buildProbes()
    private val sequence = AtomicLong(0)
    private val batchLock = Any()
    private val pendingEvents = ArrayList<ByteArray>()

    @Volatile
    private var trustTokenId: String? = null

    @Volatile
    private var policyHash: String = ""

    /** The Rust trust core version string. */
    val coreVersion: String get() = core.version

    /**
     * Sets the trust-token id minted by the server after attestation. Request
     * proofs bind to this token; [getRequestProof] requires it to be set.
     */
    fun setTrustToken(tokenId: String) {
        trustTokenId = tokenId
    }

    /**
     * Runs the enabled probes and asks the core to score the result.
     *
     * @return a [RiskAssessment] with the packed bitset, decoded signals, score,
     *   confidence, and (when a policy is loaded) the fused trust level.
     */
    fun evaluateRisk(): RiskAssessment {
        val signals = runProbes()
        val bits = RiskSignal.pack(signals)
        val (score, level) = core.evaluateRiskAndLevel(bits)
        return RiskAssessment(
            riskBits = bits,
            signals = signals,
            score = score.score,
            confidence = score.confidence,
            trustLevel = level,
        )
    }

    /**
     * Builds a per-request proof binding [requestHash] to the current trust
     * token using a fresh nonce and a strictly increasing sequence number.
     *
     * @throws KsealException with [KsealErrorCode.TRUST_TOKEN_MISSING] if no
     *   trust token has been set (complete attestation first).
     */
    fun getRequestProof(requestHash: ByteArray): RequestProof {
        val token = trustTokenId
            ?: throw KsealException(KsealErrorCode.TRUST_TOKEN_MISSING, "no trust token set; complete attestation and call setTrustToken()")
        val nonce = core.generateNonce(NONCE_LEN)
        val seq = sequence.incrementAndGet()
        val proofBytes = core.generateRequestProof(token, requestHash, nonce, seq)
        return RequestProof(
            tokenId = token,
            requestHash = requestHash,
            nonce = nonce,
            sequence = seq,
            proofBytes = proofBytes,
        )
    }

    /**
     * Records a telemetry event for [eventType], buffering it; a batch is
     * compressed and handed to the [TelemetrySink] once [KsealOptions.maxBatchEvents]
     * is reached. The event carries only the packed risk bitset and coarse
     * metadata — no PII.
     */
    fun reportEvent(eventType: EventType) {
        val signals = runProbes()
        val bits = RiskSignal.pack(signals)
        val score = core.evaluateRisk(bits)
        val event = core.createEvent(
            eventType = eventType,
            riskBits = bits,
            confidence = score.confidence,
            buildHash = options.buildHash,
            policyHash = policyHash,
            installKeyHash = installIdentityHash,
            coarseTimeBucket = coarseTimeBucket(),
            country = null,
        )
        var toFlush: List<ByteArray>? = null
        synchronized(batchLock) {
            pendingEvents += event
            if (pendingEvents.size >= options.maxBatchEvents) {
                toFlush = ArrayList(pendingEvents)
                pendingEvents.clear()
            }
        }
        toFlush?.let { emit(it) }
    }

    /** Forces any buffered telemetry to be compressed and sent. */
    fun flushTelemetry() {
        val toFlush: List<ByteArray>
        synchronized(batchLock) {
            if (pendingEvents.isEmpty()) return
            toFlush = ArrayList(pendingEvents)
            pendingEvents.clear()
        }
        emit(toFlush)
    }

    /**
     * Re-fetches and verifies the signed config (on demand — never at launch).
     * Returns true when a valid config was loaded.
     */
    fun refreshConfig(): Boolean {
        val bytes = configProvider.fetchConfig() ?: configProvider.cachedConfig() ?: return false
        if (!core.tryLoadConfig(bytes)) return false
        configProvider.persist(bytes)
        return true
    }

    /** Reports a TLS pinning failure observed by the host's transport layer. */
    fun reportPinningFailure() {
        reportEventWithBits(EventType.NETWORK_MITM, RiskSignal.PINNING_FAILURE.mask or RiskSignal.NETWORK_MITM.mask)
    }

    private fun emit(events: List<ByteArray>) {
        if (events.isEmpty()) return
        val wire = core.batchAndCompress(events)
        telemetrySink.send(wire)
    }

    private fun reportEventWithBits(eventType: EventType, bits: Long) {
        val score = core.evaluateRisk(bits)
        val event = core.createEvent(
            eventType = eventType,
            riskBits = bits,
            confidence = score.confidence,
            buildHash = options.buildHash,
            policyHash = policyHash,
            installKeyHash = installIdentityHash,
            coarseTimeBucket = coarseTimeBucket(),
            country = null,
        )
        emit(listOf(event))
    }

    private fun runProbes(): Set<RiskSignal> {
        val out = LinkedHashSet<RiskSignal>()
        for (probe in probes) {
            // Probes never throw, but defend the host app regardless.
            runCatching { out += probe.evaluate() }
        }
        return out
    }

    private fun coarseTimeBucket(): Long {
        val hourMillis = 3_600_000L
        return (clock.nowMillis() / hourMillis) * hourMillis
    }

    private fun buildProbes(): List<Probe> {
        val all: List<Probe> = listOf(
            RootDetector(env),
            EmulatorDetector(env),
            DebuggerDetector(env),
            HookDetector(env),
            IntegrityChecker(env, options.integrityPolicy),
            NetworkRiskDetector(env),
        )
        val enabled = options.enabledProbes ?: return all
        return all.filter { it.id in enabled }
    }

    private fun loadCachedConfigIfPresent() {
        configProvider.cachedConfig()?.let { core.tryLoadConfig(it) }
    }

    companion object {
        private const val NONCE_LEN = 16

        @Volatile
        private var instance: KsealSDK? = null

        /** The initialized singleton, or null if [initialize] has not run. */
        fun getInstanceOrNull(): KsealSDK? = instance

        /**
         * Initializes the SDK: loads any cached signed config and brings up the
         * Rust trust core over JNI. Safe to call once at app start; subsequent
         * calls return the existing instance.
         */
        @JvmStatic
        @JvmOverloads
        fun initialize(
            context: Context,
            tenantId: String,
            appId: String,
            apiKey: String,
            options: KsealOptions = KsealOptions(),
        ): KsealSDK {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }
                val appContext = context.applicationContext
                val env = AndroidDeviceEnvironment(appContext)
                val proofKey = KeystoreProofKeyProvider(appContext).proofKey()
                val core = NativeTrustCore.create(
                    configPublicKey = options.configPublicKey,
                    proofKey = proofKey,
                    platform = Platform.ANDROID,
                    maxBatchEvents = options.maxBatchEvents,
                )
                // Own the native handle from here: if any later init step throws,
                // free it instead of leaking the core for the process lifetime.
                val sdk = try {
                    val configProvider = FileConfigProvider(appContext)
                    val installHash = InstallIdentity(appContext).tenantScopedHash(tenantId, appId)
                    KsealSDK(
                        tenantId = tenantId,
                        appId = appId,
                        apiKey = apiKey,
                        core = core,
                        env = env,
                        options = options,
                        configProvider = configProvider,
                        telemetrySink = BufferingTelemetrySink(),
                        installIdentityHash = installHash,
                        clock = Clock.SYSTEM,
                    ).also { it.loadCachedConfigIfPresent() }
                } catch (t: Throwable) {
                    runCatching { core.close() }
                    throw t
                }
                instance = sdk
                return sdk
            }
        }

        /** Releases the singleton (primarily for tests / process teardown). */
        @JvmStatic
        fun shutdown() {
            synchronized(this) {
                instance?.let { sdk -> runCatching { (sdk.core as? AutoCloseable)?.close() } }
                instance = null
            }
        }
    }
}
