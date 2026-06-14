import Foundation

/// Optional initialization knobs. Defaults keep launch network-free and the
/// footprint small; the host overrides only what it needs.
public struct KsealDesktopOptions {
    /// Ed25519 public key (32 bytes) used to verify signed configs.
    public var configPublicKey: Data
    /// Content hash of the protected build.
    public var buildHash: String
    /// Expected code-signing baseline for the integrity probes.
    public var integrityPolicy: DesktopIntegrityPolicy
    /// Probe ids to run; nil runs the default desktop set (everything except the
    /// opt-in debugger probe, per the desktop-caution guidance).
    public var enabledProbes: Set<String>?
    /// Telemetry events buffered before a batch is flushed.
    public var maxBatchEvents: Int
    /// Enterprise compatibility controls. `nil` reads the OS-managed
    /// configuration at `initialize` (strict when none); a non-nil value
    /// overrides it (useful for hosts that supply the policy directly / tests).
    public var enterprisePolicy: EnterprisePolicy?

    public init(
        configPublicKey: Data = Data(repeating: 0, count: 32),
        buildHash: String = "",
        integrityPolicy: DesktopIntegrityPolicy = DesktopIntegrityPolicy(),
        enabledProbes: Set<String>? = nil,
        maxBatchEvents: Int = 32,
        enterprisePolicy: EnterprisePolicy? = nil
    ) {
        self.configPublicKey = configPublicKey
        self.buildHash = buildHash
        self.integrityPolicy = integrityPolicy
        self.enabledProbes = enabledProbes
        self.maxBatchEvents = maxBatchEvents
        self.enterprisePolicy = enterprisePolicy
    }
}

/// Public entry point to the kseal **macOS desktop** SDK.
///
/// Wraps the shared Rust trust core (via the C ABI) and the native macOS
/// integrity probes (code signature, notarization, hardened runtime, dylib
/// injection). The SDK gathers local integrity signals, hands the packed risk
/// bitset to the core for scoring, drives the server trust flow, and produces
/// per-request proofs — but never makes the final trust decision (the server
/// does). It performs **no network I/O at launch**: probes run lazily on demand,
/// telemetry is batched, and the trust session is established only when the host
/// calls `establishTrustSession`.
public final class KsealDesktop {

    private let core: TrustCore
    private let env: DesktopEnvironment
    private let options: KsealDesktopOptions
    private let configProvider: ConfigProvider
    private let telemetrySink: TelemetrySink
    private let attestor: CodeIntegrityAttestor
    private let installIdentityHash: String
    private let clock: Clock

    /// Whether the request-proof key is sealed by a hardware-backed element
    /// (Secure Enclave). False on hosts that fall back to the software store.
    public let proofKeyIsHardwareBacked: Bool

    /// The effective enterprise compatibility controls in force (surfaced for
    /// auditing what a managed configuration relaxed).
    public let enterprisePolicy: EnterprisePolicy

    private let probes: [Probe]
    private let lock = NSLock()
    private var sequence: Int64 = 0
    private var pendingEvents: [Data] = []
    private var trustTokenId: String?
    private var policyHash: String = ""

    init(
        core: TrustCore,
        env: DesktopEnvironment,
        options: KsealDesktopOptions,
        configProvider: ConfigProvider,
        telemetrySink: TelemetrySink,
        attestor: CodeIntegrityAttestor,
        installIdentityHash: String,
        clock: Clock,
        proofKeyIsHardwareBacked: Bool = false,
        enterprisePolicy: EnterprisePolicy = .strict
    ) {
        self.core = core
        self.env = env
        self.options = options
        self.configProvider = configProvider
        self.telemetrySink = telemetrySink
        self.attestor = attestor
        self.installIdentityHash = installIdentityHash
        self.clock = clock
        self.proofKeyIsHardwareBacked = proofKeyIsHardwareBacked
        self.enterprisePolicy = enterprisePolicy
        self.probes = Self.buildProbes(env: env, options: options, enterprise: enterprisePolicy)
    }

    /// The Rust trust core version string.
    public var coreVersion: String { core.version }

    /// The stable, tenant-scoped install identity hash (non-PII) bound to the
    /// trust session.
    public var instanceId: String { installIdentityHash }

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

    /// Establishes a trust session against the server: fetch nonce, evaluate
    /// local integrity, build the platform attestation, and verify. On success
    /// the minted trust token is stored so `getRequestProof` can bind to it.
    ///
    /// This is the only network call the SDK initiates, and it never runs at
    /// launch — the host invokes it explicitly (typically off the main thread).
    @discardableResult
    public func establishTrustSession(using client: TrustSessionClient) throws -> TrustSession {
        let nonce = try client.getNonce()
        let signals = runProbes()
        let bits = RiskSignal.pack(signals)
        let info = env.codeSigningInfo()
        let token = attestor.attestationToken(for: info)

        let session = try client.verifyAttestation(
            nonce: nonce,
            riskBitset: bits,
            buildHash: options.buildHash,
            policyHash: currentPolicyHash(),
            instanceId: installIdentityHash,
            attestationToken: token
        )
        if session.accepted, !session.tokenId.isEmpty {
            setTrustToken(session.tokenId)
        }
        return session
    }

    /// Builds a per-request proof binding `requestHash` to the current trust
    /// token using a fresh nonce and a strictly increasing sequence number.
    public func getRequestProof(requestHash: Data) throws -> RequestProof {
        lock.lock()
        guard let token = trustTokenId else {
            lock.unlock()
            throw TrustCoreError(kind: .trustTokenMissing, message: "no trust token set; call establishTrustSession() or setTrustToken()")
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

    /// Builds a request proof for `requestHash` and asks the server to validate
    /// it, returning the ALLOW / STEP_UP / DENY decision.
    public func authorizeRequest(requestHash: Data, using client: TrustSessionClient) throws -> RequestProofDecision {
        let proof = try getRequestProof(requestHash: requestHash)
        return try client.validateRequestProof(proof)
    }

    /// Records a telemetry event, buffering it; a batch is compressed and handed
    /// to the `TelemetrySink` once `maxBatchEvents` is reached. The event carries
    /// only the packed risk bitset and coarse metadata — no PII.
    public func reportEvent(_ eventType: EventType) {
        let bits = RiskSignal.pack(runProbes())
        // Minimal telemetry verbosity drops clean (no-signal) events to cut
        // volume; standard/verbose record everything the host reports.
        if enterprisePolicy.telemetryVerbosity == .minimal && bits == 0 { return }
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

    private func currentPolicyHash() -> String {
        lock.lock(); defer { lock.unlock() }
        return policyHash
    }

    private func makeEvent(_ eventType: EventType, bits: UInt64) throws -> Data {
        let score = try core.evaluateRisk(bits)
        return try core.createEvent(
            eventType: eventType,
            riskBits: bits,
            confidence: score.confidence,
            buildHash: options.buildHash,
            policyHash: currentPolicyHash(),
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
        // Fail closed for regulated deployments: if hardware-backed proof keys
        // are required but unavailable, surface the missing-secure-hardware
        // signal so the server can adjudicate it. Off by default.
        if enterprisePolicy.requireHardwareBackedProofKey && !proofKeyIsHardwareBacked {
            out.insert(.secureHwMissing)
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

    private static func buildProbes(
        env: DesktopEnvironment,
        options: KsealDesktopOptions,
        enterprise: EnterprisePolicy
    ) -> [Probe] {
        let policy = options.integrityPolicy
        let all: [Probe] = [
            CodeSignatureProbe(env, policy: policy),
            NotarizationProbe(env, policy: policy),
            HardenedRuntimeProbe(env, policy: policy),
            DylibInjectionProbe(env, isAllowed: enterprise.allowsModule),
            DebuggerProbe(env),
        ]
        let selected: [Probe]
        if let enabled = options.enabledProbes {
            selected = all.filter { enabled.contains($0.id) }
        } else {
            // Default desktop set omits the aggressive anti-debug probe; the host
            // opts in explicitly (see ARCHITECTURE.md desktop caution).
            selected = all.filter { $0.id != "macos.debugger" }
        }
        // A managed developer machine may permit debugging: drop the debugger
        // probe so legitimate debugging does not raise a signal.
        return enterprise.permitDebugger ? selected.filter { $0.id != "macos.debugger" } : selected
    }

    // MARK: - Lifecycle

    private static let nonceLength = 16
    private static let lockSingleton = NSLock()
    private static var instance: KsealDesktop?

    /// The initialized singleton, or nil if `initialize` has not run.
    public static func shared() -> KsealDesktop? {
        lockSingleton.lock(); defer { lockSingleton.unlock() }
        return instance
    }

    /// Initializes the SDK: loads any cached signed config and brings up the
    /// Rust trust core. Safe to call once at app start; subsequent calls return
    /// the existing instance. Performs no network I/O.
    @discardableResult
    public static func initialize(
        tenantId: String,
        appId: String,
        options: KsealDesktopOptions = KsealDesktopOptions(),
        attestor: CodeIntegrityAttestor = LocalCodeIntegrityAttestor()
    ) throws -> KsealDesktop {
        lockSingleton.lock(); defer { lockSingleton.unlock() }
        if let existing = instance { return existing }

        let storageDir = storageDirectory(tenantId: tenantId, appId: appId)
        let env = makeDefaultDesktopEnvironment()
        let keyStore = makeDefaultHardwareKeyStore(
            label: StorageScope.component(tenantId: tenantId, appId: appId))
        let proofKeyProvider = HardwareBoundProofKeyProvider(directory: storageDir, store: keyStore)
        let proofKey = proofKeyProvider.proofKey()
        let core = try NativeTrustCore.create(
            configPublicKey: options.configPublicKey,
            proofKey: proofKey,
            platform: .desktopMac,
            maxBatchEvents: options.maxBatchEvents
        )
        let configProvider = FileConfigProvider(directory: storageDir)
        let installHash = InstallIdentity(directory: storageDir).tenantScopedHash(tenantId: tenantId, appId: appId)
        // Read the OS-managed enterprise configuration unless the host supplied
        // one directly; absent any managed config this is the strict baseline.
        let enterprisePolicy = options.enterprisePolicy ?? makeDefaultEnterprisePolicyProvider().currentPolicy()

        let sdk = KsealDesktop(
            core: core,
            env: env,
            options: options,
            configProvider: configProvider,
            telemetrySink: BufferingTelemetrySink(),
            attestor: attestor,
            installIdentityHash: installHash,
            clock: SystemClock(),
            proofKeyIsHardwareBacked: proofKeyProvider.isHardwareBacked,
            enterprisePolicy: enterprisePolicy
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

    /// Per-tenant/app private storage root. Scoping the directory by a
    /// collision-resistant `tenant+app` component keeps each tenant/app's config,
    /// proof key, and install id isolated when several share one user account.
    private static func storageDirectory(tenantId: String, appId: String) -> URL {
        let fm = FileManager.default
        let base: URL
        if let support = try? fm.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        ) {
            base = support
        } else {
            base = fm.temporaryDirectory
        }
        let scoped = base.appendingPathComponent(
            StorageScope.component(tenantId: tenantId, appId: appId), isDirectory: true)
        try? fm.createDirectory(at: scoped, withIntermediateDirectories: true)
        return scoped
    }
}
