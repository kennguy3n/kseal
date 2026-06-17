package io.kseal.sdk

import android.content.Context
import io.kseal.sdk.internal.NativeTrustCore
import io.kseal.sdk.internal.TrustCore
import io.kseal.sdk.probes.AccessibilityAbuseDetector
import io.kseal.sdk.probes.AndroidDeviceEnvironment
import io.kseal.sdk.probes.DebuggerDetector
import io.kseal.sdk.probes.DeviceEnvironment
import io.kseal.sdk.probes.EmulatorDetector
import io.kseal.sdk.probes.HookDetector
import io.kseal.sdk.probes.ImeDetector
import io.kseal.sdk.probes.IntegrityChecker
import io.kseal.sdk.probes.IntegrityPolicy
import io.kseal.sdk.probes.NetworkRiskDetector
import io.kseal.sdk.probes.OverlayDetector
import io.kseal.sdk.probes.Probe
import io.kseal.sdk.probes.RemoteAccessDetector
import io.kseal.sdk.probes.RootDetector
import io.kseal.sdk.probes.ScreenCaptureDetector
import io.kseal.sdk.probes.SelfIntegrityDetector
import io.kseal.sdk.probes.TamperPolicy
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Optional initialization knobs. Defaults keep launch network-free and the
 * footprint small; the host overrides only what it needs.
 *
 * @property configPublicKey Ed25519 public key (32 bytes) used to verify signed configs.
 * @property buildHash content hash of the protected build (from the Gradle hardening plugin).
 * @property integrityPolicy expected signing certs / installers for the integrity probe.
 * @property tamperPolicy expected code/artifact SHA-256 baseline for the runtime self-integrity probe.
 * @property enabledProbes the probe ids to run; null runs all (tenants include only what they need).
 * @property maxBatchEvents telemetry events buffered before a batch is flushed.
 */
data class KsealOptions(
    val configPublicKey: ByteArray = ByteArray(32),
    val buildHash: String = "",
    val integrityPolicy: IntegrityPolicy = IntegrityPolicy(),
    val tamperPolicy: TamperPolicy = TamperPolicy(),
    val enabledProbes: Set<String>? = null,
    val maxBatchEvents: Int = 32,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KsealOptions) return false
        return configPublicKey.contentEquals(other.configPublicKey) &&
            buildHash == other.buildHash &&
            integrityPolicy == other.integrityPolicy &&
            tamperPolicy == other.tamperPolicy &&
            enabledProbes == other.enabledProbes &&
            maxBatchEvents == other.maxBatchEvents
    }

    override fun hashCode(): Int {
        var result = configPublicKey.contentHashCode()
        result = 31 * result + buildHash.hashCode()
        result = 31 * result + integrityPolicy.hashCode()
        result = 31 * result + tamperPolicy.hashCode()
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

    private val schedulerLock = Any()
    private var scheduler: ScheduledExecutorService? = null
    private var reattestTask: ScheduledFuture<*>? = null

    // Serializes the read-apply-compare in [applyKillSwitch] so concurrent
    // callers (the heartbeat and a direct host call) can't each observe a stale
    // `before` and double- or miss-fire [onKillSwitchChanged]. The core state is
    // always correct on its own; this only guards the transition notification.
    private val killSwitchLock = Any()

    /**
     * Active-response hook (Phase 3.2). Invoked with the locally re-computed
     * trust decision — using the exact mapping the server applies
     * (`risk.Decision`) — on each re-attestation cycle and from
     * [evaluateTrustDecision]. The default is a no-op: the SDK never locks,
     * forces MFA, or wipes on its own; the host decides what a `STEP_UP` /
     * `DENY` means for its UX.
     *
     * Example — step-up on elevated risk, lock on denial:
     * ```
     * sdk.onTrustDecision = { level, decision ->
     *     when (decision) {
     *         Decision.STEP_UP -> requireBiometricReauth()
     *         Decision.DENY    -> lockSensitiveScreens()
     *         else             -> Unit
     *     }
     * }
     * ```
     */
    @Volatile
    var onTrustDecision: ((TrustLevel, Decision) -> Unit)? = null

    /**
     * Forced-degrade hook (Phase 3.3) fired when a server-driven kill switch
     * takes effect or is lifted; the boolean is the new [isKilled] state.
     * Default no-op — the host decides how to degrade (e.g. read-only mode).
     */
    @Volatile
    var onKillSwitchChanged: ((Boolean) -> Unit)? = null

    /** The Rust trust core version string. */
    val coreVersion: String get() = core.version

    /**
     * Whether a valid server-driven kill switch currently disables the app.
     * Reads local state only; fail-safe (false) unless an Ed25519-valid
     * `DISABLE` has been applied via [applyKillSwitch] / [refreshKillSwitch].
     */
    val isKilled: Boolean get() = core.isKilled()

    /**
     * The active policy's opt-in re-attestation cadence in seconds, or 0 when
     * continuous mode is off. Local read — never touches the network.
     */
    val reattestIntervalSecs: Long get() = core.reattestIntervalSecs()

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

    /**
     * Re-runs probes, scores them under the active policy, and returns the
     * trust [Decision] using the exact mapping the server applies. The SDK only
     * surfaces this for the host's active-response hooks; it never enforces it.
     */
    fun evaluateTrustDecision(): Pair<TrustLevel, Decision> {
        val assessment = evaluateRisk()
        // Resolve level + decision in one core read so a concurrent config swap
        // can't surface a mismatched pair (e.g. HIGH_RISK with ALLOW).
        return core.decisionWithLevel(assessment.riskBits)
    }

    /**
     * Verifies and applies a serialized `kseal.v1.SignedKillSwitch` (typically
     * obtained by the host from its own `GetConfig` response). Fail-safe: a
     * forged or absent command never disables the app; only an Ed25519-valid
     * `DISABLE` does, and a valid `ENABLE` lifts it. Returns the resulting
     * [isKilled] state and fires [onKillSwitchChanged] on a transition.
     */
    fun applyKillSwitch(signedKillSwitchBytes: ByteArray): Boolean {
        val after: Boolean
        val transitioned: Boolean
        synchronized(killSwitchLock) {
            val before = core.isKilled()
            after = core.applyKillSwitch(signedKillSwitchBytes)
            transitioned = after != before
        }
        // Fire outside the lock so a host callback can't re-enter and deadlock.
        if (transitioned) onKillSwitchChanged?.invoke(after)
        return after
    }

    /**
     * Pulls the latest signed kill switch from the [ConfigProvider] (on demand —
     * never at launch) and applies it. Returns the resulting [isKilled] state;
     * a no-op returning the current state when the provider has none.
     */
    fun refreshKillSwitch(): Boolean {
        val bytes = configProvider.fetchKillSwitch() ?: return core.isKilled()
        return applyKillSwitch(bytes)
    }

    /**
     * Starts the opt-in periodic re-attestation heartbeat (Phase 3.1). No-op
     * returning false unless the active policy set a positive
     * `reattest_interval_secs`, so the "no launch-time network call" invariant
     * holds until the host both loads a continuous-mode policy and explicitly
     * opts in by calling this. Idempotent; a running scheduler is reused.
     */
    fun startContinuousProtection(): Boolean {
        val interval = core.reattestIntervalSecs()
        if (interval <= 0L) return false
        synchronized(schedulerLock) {
            if (reattestTask != null) return true
            val exec = scheduler ?: Executors.newSingleThreadScheduledExecutor { r ->
                Thread(r, "kseal-reattest").apply { isDaemon = true }
            }.also { scheduler = it }
            reattestTask = exec.scheduleAtFixedRate(
                { runCatching { runReattestCycle() } },
                interval,
                interval,
                TimeUnit.SECONDS,
            )
        }
        return true
    }

    /**
     * Stops the periodic heartbeat and releases its executor thread, so no
     * `kseal-reattest` daemon lingers while continuous mode is off (matching the
     * iOS/macOS timer release). A later [startContinuousProtection] spins up a
     * fresh executor. The SDK remains usable on demand.
     */
    fun stopContinuousProtection() {
        shutdownScheduler()
    }

    /**
     * Runs one re-attestation cycle immediately. Wire this to the host's
     * foreground lifecycle hook so trust is re-evaluated on app resume.
     */
    fun onAppForeground() {
        runCatching { runReattestCycle() }
    }

    /**
     * One re-attestation cycle: re-run probes, recompute and surface the trust
     * decision, re-validate the signed config, and — as coverage rises with
     * risk (mirroring the server's NextChecks escalation) — pull the latest
     * kill switch when the level reaches `MEDIUM_RISK`. Pure and dependency-
     * injected so tests can drive it directly without the scheduler.
     */
    internal fun runReattestCycle() {
        val assessment = evaluateRisk()
        // One core read yields a consistent (level, decision) pair even if a
        // config reload races this cycle; both feed the host hook and the
        // escalation gate below.
        val (level, decision) = core.decisionWithLevel(assessment.riskBits)
        onTrustDecision?.invoke(level, decision)
        // Baseline re-validation: refresh the signed config. The default
        // provider returns null and falls back to cache (no network).
        refreshConfig()
        // Escalation: at MEDIUM_RISK or above, also pull + apply the latest
        // kill switch so a server-driven forced degrade surfaces promptly.
        if (level.code >= TrustLevel.MEDIUM_RISK.code) {
            refreshKillSwitch()
        }
    }

    private fun shutdownScheduler() {
        synchronized(schedulerLock) {
            reattestTask?.cancel(false)
            reattestTask = null
            scheduler?.shutdownNow()
            scheduler = null
        }
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
            SelfIntegrityDetector(env, options.tamperPolicy),
            NetworkRiskDetector(env),
            // Wave-2 fraud-vector RASP probes, registered together for layout
            // parity. Some are live and emit fusion-weighted risk signals while
            // others are still no-op stubs pending implementation; each probe
            // gates its own behaviour independently of the rest.
            ScreenCaptureDetector(),
            OverlayDetector(env),
            AccessibilityAbuseDetector(env),
            ImeDetector(env),
            RemoteAccessDetector(env),
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
                instance?.let { sdk ->
                    runCatching { sdk.shutdownScheduler() }
                    runCatching { (sdk.core as? AutoCloseable)?.close() }
                }
                instance = null
            }
        }
    }
}
