import Foundation

/// Optional initialization knobs. Defaults keep launch network-free and the
/// footprint small; the host overrides only what it needs.
public struct KsealOptions {
    /// Ed25519 public key (32 bytes) used to verify signed configs.
    public var configPublicKey: Data
    /// Content hash of the protected build.
    public var buildHash: String
    /// Expected distribution / bundle id for the integrity probe.
    public var integrityPolicy: IntegrityPolicy
    /// Expected code/artifact SHA-256 baseline for the runtime self-integrity probe.
    public var tamperPolicy: TamperPolicy
    /// Probe ids to run; nil runs all (tenants include only what they need).
    public var enabledProbes: Set<String>?
    /// Telemetry events buffered before a batch is flushed.
    public var maxBatchEvents: Int

    public init(
        configPublicKey: Data = Data(repeating: 0, count: 32),
        buildHash: String = "",
        integrityPolicy: IntegrityPolicy = IntegrityPolicy(),
        tamperPolicy: TamperPolicy = TamperPolicy(),
        enabledProbes: Set<String>? = nil,
        maxBatchEvents: Int = 32
    ) {
        self.configPublicKey = configPublicKey
        self.buildHash = buildHash
        self.integrityPolicy = integrityPolicy
        self.tamperPolicy = tamperPolicy
        self.enabledProbes = enabledProbes
        self.maxBatchEvents = maxBatchEvents
    }
}

/// Public entry point to the kseal device SDK.
///
/// Wraps the shared Rust trust core (via the C ABI) and the native Apple RASP
/// probes. The SDK gathers signals, hands the packed risk bitset to the core
/// for scoring, and produces per-request proofs — but never makes the final
/// trust decision (the server does). It performs **no network I/O at launch**:
/// probes run lazily on demand and telemetry is batched.
public final class KsealSDK {

    private let tenantId: String
    private let appId: String
    private let apiKey: String
    private let core: TrustCore
    private let env: DeviceEnvironment
    private let options: KsealOptions
    private let configProvider: ConfigProvider
    private let telemetrySink: TelemetrySink
    private let installIdentityHash: String
    private let clock: Clock

    private let probes: [Probe]
    private let lock = NSLock()
    private var sequence: Int64 = 0
    private var pendingEvents: [Data] = []
    private var trustTokenId: String?
    private var policyHash: String = ""

    private let reattestQueue = DispatchQueue(label: "io.kseal.reattest")
    // Serializes the read-apply-compare in `applyKillSwitch` so concurrent
    // callers (the heartbeat and a direct host call) can't each observe a stale
    // `before` and double- or miss-fire `onKillSwitchChanged`. The core state is
    // always correct on its own; this only guards the transition notification.
    private let killSwitchLock = NSLock()
    private var reattestTimer: DispatchSourceTimer?
    private var _onTrustDecision: ((TrustLevel, Decision) -> Void)?
    private var _onKillSwitchChanged: ((Bool) -> Void)?

    /// Active-response hook (Phase 3.2). Invoked with the locally re-computed
    /// trust decision — using the exact mapping the server applies
    /// (`risk.Decision`) — on each re-attestation cycle and from
    /// `evaluateTrustDecision()`. Default is a no-op: the SDK never locks, forces
    /// MFA, or wipes on its own; the host decides what `.stepUp` / `.deny` means.
    ///
    /// Example — step-up on elevated risk, lock on denial:
    /// ```swift
    /// sdk.onTrustDecision = { level, decision in
    ///     switch decision {
    ///     case .stepUp: requireBiometricReauth()
    ///     case .deny:   lockSensitiveScreens()
    ///     default:      break
    ///     }
    /// }
    /// ```
    public var onTrustDecision: ((TrustLevel, Decision) -> Void)? {
        get { lock.lock(); defer { lock.unlock() }; return _onTrustDecision }
        set { lock.lock(); defer { lock.unlock() }; _onTrustDecision = newValue }
    }

    /// Forced-degrade hook (Phase 3.3) fired when a server-driven kill switch
    /// takes effect or is lifted; the bool is the new `isKilled` state. Default
    /// no-op — the host decides how to degrade (e.g. read-only mode).
    public var onKillSwitchChanged: ((Bool) -> Void)? {
        get { lock.lock(); defer { lock.unlock() }; return _onKillSwitchChanged }
        set { lock.lock(); defer { lock.unlock() }; _onKillSwitchChanged = newValue }
    }

    init(
        tenantId: String,
        appId: String,
        apiKey: String,
        core: TrustCore,
        env: DeviceEnvironment,
        options: KsealOptions,
        configProvider: ConfigProvider,
        telemetrySink: TelemetrySink,
        installIdentityHash: String,
        clock: Clock
    ) {
        self.tenantId = tenantId
        self.appId = appId
        self.apiKey = apiKey
        self.core = core
        self.env = env
        self.options = options
        self.configProvider = configProvider
        self.telemetrySink = telemetrySink
        self.installIdentityHash = installIdentityHash
        self.clock = clock
        self.probes = Self.buildProbes(env: env, options: options)
    }

    /// The Rust trust core version string.
    public var coreVersion: String { core.version }

    /// Sets the trust-token id minted by the server after attestation. Request
    /// proofs bind to this token; `getRequestProof` requires it to be set.
    public func setTrustToken(_ tokenId: String) {
        lock.lock(); defer { lock.unlock() }
        trustTokenId = tokenId
    }

    /// Runs the enabled probes and asks the core to score the result.
    public func evaluateRisk() throws -> RiskAssessment {
        let signals = runProbes()
        let bits = RiskSignal.pack(signals)
        let (score, level) = try core.evaluateRiskAndLevel(bits)
        return RiskAssessment(
            riskBits: bits,
            signals: signals,
            score: score.score,
            confidence: score.confidence,
            trustLevel: level
        )
    }

    /// Builds a per-request proof binding `requestHash` to the current trust
    /// token using a fresh nonce and a strictly increasing sequence number.
    public func getRequestProof(requestHash: Data) throws -> RequestProof {
        lock.lock()
        guard let token = trustTokenId else {
            lock.unlock()
            throw TrustCoreError(kind: .trustTokenMissing, message: "no trust token set; complete attestation and call setTrustToken()")
        }
        sequence += 1
        let seq = sequence
        lock.unlock()

        let nonce = try core.generateNonce(Self.nonceLength)
        let proofBytes = try core.generateRequestProof(
            tokenId: token, requestHash: requestHash, nonce: nonce, sequence: seq
        )
        return RequestProof(
            tokenId: token, requestHash: requestHash, nonce: nonce, sequence: seq, proofBytes: proofBytes
        )
    }

    /// Records a telemetry event, buffering it; a batch is compressed and handed
    /// to the `TelemetrySink` once `maxBatchEvents` is reached. The event carries
    /// only the packed risk bitset and coarse metadata — no PII.
    public func reportEvent(_ eventType: EventType) {
        let bits = RiskSignal.pack(runProbes())
        guard let event = try? makeEvent(eventType, bits: bits) else { return }

        var toFlush: [Data]?
        lock.lock()
        pendingEvents.append(event)
        if pendingEvents.count >= options.maxBatchEvents {
            toFlush = pendingEvents
            pendingEvents.removeAll()
        }
        lock.unlock()

        if let toFlush { emit(toFlush) }
    }

    /// Forces any buffered telemetry to be compressed and sent.
    public func flushTelemetry() {
        lock.lock()
        guard !pendingEvents.isEmpty else { lock.unlock(); return }
        let toFlush = pendingEvents
        pendingEvents.removeAll()
        lock.unlock()
        emit(toFlush)
    }

    /// Re-fetches and verifies the signed config (on demand — never at launch).
    /// Returns true when a valid config was loaded.
    @discardableResult
    public func refreshConfig() -> Bool {
        guard let bytes = configProvider.fetchConfig() ?? configProvider.cachedConfig() else { return false }
        guard core.tryLoadConfig(bytes) else { return false }
        configProvider.persist(bytes)
        return true
    }

    /// Reports a TLS pinning failure observed by the host's transport layer.
    public func reportPinningFailure() {
        let bits = RiskSignal.pinningFailure.mask | RiskSignal.networkMitm.mask
        guard let event = try? makeEvent(.networkMitm, bits: bits) else { return }
        emit([event])
    }

    // MARK: - Continuous protection & active response (Phase 3)

    /// Whether a valid server-driven kill switch currently disables the app.
    /// Reads local state only; fail-safe (false) unless an Ed25519-valid
    /// `DISABLE` was applied via `applyKillSwitch` / `refreshKillSwitch`.
    public var isKilled: Bool { core.isKilled() }

    /// The active policy's opt-in re-attestation cadence in seconds, or 0 when
    /// continuous mode is off. Local read — never touches the network.
    public var reattestIntervalSecs: UInt32 { core.reattestIntervalSecs() }

    /// Re-runs probes, scores them under the active policy, and returns the
    /// trust `Decision` using the exact mapping the server applies. The SDK only
    /// surfaces this for the host's active-response hooks; it never enforces it.
    public func evaluateTrustDecision() throws -> (TrustLevel, Decision) {
        let assessment = try evaluateRisk()
        // Resolve level + decision in one core read so a concurrent config swap
        // can't surface a mismatched pair (e.g. .highRisk with .allow).
        return core.decisionWithLevel(assessment.riskBits)
    }

    /// Verifies and applies a serialized `kseal.v1.SignedKillSwitch` (typically
    /// obtained by the host from its own `GetConfig` response). Fail-safe: a
    /// forged or absent command never disables the app; only an Ed25519-valid
    /// `DISABLE` does, and a valid `ENABLE` lifts it. Returns the resulting
    /// `isKilled` state and fires `onKillSwitchChanged` on a transition.
    @discardableResult
    public func applyKillSwitch(_ signedKillSwitchBytes: Data) -> Bool {
        killSwitchLock.lock()
        let before = core.isKilled()
        let after = core.applyKillSwitch(signedKillSwitchBytes)
        let transitioned = after != before
        killSwitchLock.unlock()
        // Fire outside the lock so a host callback can't re-enter and deadlock.
        if transitioned {
            lock.lock(); let cb = _onKillSwitchChanged; lock.unlock()
            cb?(after)
        }
        return after
    }

    /// Pulls the latest signed kill switch from the `ConfigProvider` (on demand —
    /// never at launch) and applies it. Returns the resulting `isKilled` state;
    /// a no-op returning the current state when the provider has none.
    @discardableResult
    public func refreshKillSwitch() -> Bool {
        guard let bytes = configProvider.fetchKillSwitch() else { return core.isKilled() }
        return applyKillSwitch(bytes)
    }

    /// Starts the opt-in periodic re-attestation heartbeat (Phase 3.1). No-op
    /// returning false unless the active policy set a positive
    /// `reattest_interval_secs`, so the "no launch-time network call" invariant
    /// holds until the host both loads a continuous-mode policy and explicitly
    /// opts in by calling this. Idempotent; a running timer is reused.
    @discardableResult
    public func startContinuousProtection() -> Bool {
        let interval = core.reattestIntervalSecs()
        guard interval > 0 else { return false }
        lock.lock(); defer { lock.unlock() }
        if reattestTimer != nil { return true }
        let timer = DispatchSource.makeTimerSource(queue: reattestQueue)
        // Fire after one interval (no immediate tick at start).
        timer.schedule(deadline: .now() + .seconds(Int(interval)), repeating: .seconds(Int(interval)))
        timer.setEventHandler { [weak self] in self?.runReattestCycle() }
        reattestTimer = timer
        timer.resume()
        return true
    }

    /// Stops the periodic heartbeat. The SDK remains usable on demand.
    public func stopContinuousProtection() {
        lock.lock(); let timer = reattestTimer; reattestTimer = nil; lock.unlock()
        timer?.cancel()
    }

    /// Runs one re-attestation cycle immediately. Wire this to the host's
    /// foreground lifecycle notification so trust is re-evaluated on resume.
    public func onAppForeground() {
        runReattestCycle()
    }

    /// One re-attestation cycle: re-run probes, recompute and surface the trust
    /// decision, re-validate the signed config, and always pull the latest kill
    /// switch so a server-driven forced degrade surfaces promptly regardless of
    /// risk level. Internal so tests can drive it directly without the timer.
    func runReattestCycle() {
        guard let assessment = try? evaluateRisk() else { return }
        // One core read yields a consistent (level, decision) pair even if a
        // config reload races this cycle; both feed the hook and the escalation
        // gate below.
        let (level, decision) = core.decisionWithLevel(assessment.riskBits)
        lock.lock(); let cb = _onTrustDecision; lock.unlock()
        cb?(level, decision)
        // Baseline re-validation: refresh the signed config (default provider
        // returns nil and falls back to cache — no network).
        refreshConfig()
        // Always pull + apply the latest kill switch so a server-driven
        // forced degrade surfaces promptly regardless of risk level.
        _ = refreshKillSwitch()
    }

    // MARK: - Internals

    private func makeEvent(_ eventType: EventType, bits: UInt64) throws -> Data {
        let score = try core.evaluateRisk(bits)
        return try core.createEvent(
            eventType: eventType,
            riskBits: bits,
            confidence: score.confidence,
            buildHash: options.buildHash,
            policyHash: policyHash,
            installKeyHash: installIdentityHash,
            coarseTimeBucket: coarseTimeBucket(),
            country: nil
        )
    }

    private func emit(_ events: [Data]) {
        guard !events.isEmpty, let wire = try? core.batchAndCompress(events) else { return }
        telemetrySink.send(wire)
    }

    private func runProbes() -> Set<RiskSignal> {
        var out = Set<RiskSignal>()
        for probe in probes {
            out.formUnion(probe.evaluate())
        }
        return out
    }

    private func coarseTimeBucket() -> Int64 {
        let hourMillis: Int64 = 3_600_000
        return (clock.nowMillis() / hourMillis) * hourMillis
    }

    private func loadCachedConfigIfPresent() {
        if let cached = configProvider.cachedConfig() {
            _ = core.tryLoadConfig(cached)
        }
    }

    private static func buildProbes(env: DeviceEnvironment, options: KsealOptions) -> [Probe] {
        let all: [Probe] = [
            JailbreakDetector(env),
            SimulatorDetector(env),
            DebuggerDetector(env),
            HookDetector(env),
            IntegrityChecker(env, policy: options.integrityPolicy),
            SelfIntegrityDetector(env, policy: options.tamperPolicy),
            NetworkRiskDetector(env),
            // Wave-2 fraud-vector RASP stubs: registered for cross-platform
            // parity but currently emit no signals (zero runtime behaviour
            // change). overlay/accessibility/ime are permanent no-ops on iOS.
            ScreenCaptureDetector(),
            OverlayDetector(),
            AccessibilityAbuseDetector(),
            ImeDetector(),
            RemoteAccessDetector(),
        ]
        guard let enabled = options.enabledProbes else { return all }
        return all.filter { enabled.contains($0.id) }
    }

    // MARK: - Lifecycle

    private static let nonceLength = 16
    private static let lockSingleton = NSLock()
    private static var instance: KsealSDK?

    /// The initialized singleton, or nil if `initialize` has not run.
    public static func shared() -> KsealSDK? {
        lockSingleton.lock(); defer { lockSingleton.unlock() }
        return instance
    }

    /// Initializes the SDK: loads any cached signed config and brings up the
    /// Rust trust core. Safe to call once at app start; subsequent calls return
    /// the existing instance.
    @discardableResult
    public static func initialize(
        tenantId: String,
        appId: String,
        apiKey: String,
        options: KsealOptions = KsealOptions()
    ) throws -> KsealSDK {
        lockSingleton.lock(); defer { lockSingleton.unlock() }
        if let existing = instance { return existing }

        let storageDir = storageDirectory()
        let env = makeDefaultDeviceEnvironment()
        let proofKey = DefaultProofKeyProvider(directory: storageDir).proofKey()
        let core = try NativeTrustCore.create(
            configPublicKey: options.configPublicKey,
            proofKey: proofKey,
            platform: .ios,
            maxBatchEvents: options.maxBatchEvents
        )
        let configProvider = FileConfigProvider(directory: storageDir)
        let installHash = InstallIdentity(directory: storageDir).tenantScopedHash(tenantId: tenantId, appId: appId)

        let sdk = KsealSDK(
            tenantId: tenantId,
            appId: appId,
            apiKey: apiKey,
            core: core,
            env: env,
            options: options,
            configProvider: configProvider,
            telemetrySink: BufferingTelemetrySink(),
            installIdentityHash: installHash,
            clock: SystemClock()
        )
        sdk.loadCachedConfigIfPresent()
        instance = sdk
        return sdk
    }

    /// Releases the singleton (primarily for tests / process teardown).
    public static func shutdownForTesting() {
        lockSingleton.lock(); defer { lockSingleton.unlock() }
        instance?.stopContinuousProtection()
        instance = nil
    }

    private static func storageDirectory() -> URL {
        let fm = FileManager.default
        if let support = try? fm.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        ) {
            return support
        }
        return fm.temporaryDirectory
    }
}
