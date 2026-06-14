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
    /// Probe ids to run; nil runs all (tenants include only what they need).
    public var enabledProbes: Set<String>?
    /// Telemetry events buffered before a batch is flushed.
    public var maxBatchEvents: Int

    public init(
        configPublicKey: Data = Data(repeating: 0, count: 32),
        buildHash: String = "",
        integrityPolicy: IntegrityPolicy = IntegrityPolicy(),
        enabledProbes: Set<String>? = nil,
        maxBatchEvents: Int = 32
    ) {
        self.configPublicKey = configPublicKey
        self.buildHash = buildHash
        self.integrityPolicy = integrityPolicy
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
            NetworkRiskDetector(env),
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
