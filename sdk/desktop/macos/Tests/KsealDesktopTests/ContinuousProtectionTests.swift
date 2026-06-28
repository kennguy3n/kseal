import XCTest
@testable import KsealDesktop

/// Phase 3 continuous-protection / active-response wiring.
///
/// The deterministic tests drive a `FakeTrustCore` so the re-attestation cycle,
/// `onTrustDecision` dispatch, and kill-switch surfacing are exercised without
/// the native library or Ed25519 signing. The final test is a true end-to-end
/// check against the **real** Rust core over the C ABI: a server-signed,
/// build-scoped kill switch drives the SDK into the killed (degraded) state,
/// and a forged one never does (fail-safe).
final class ContinuousProtectionTests: XCTestCase {

    private struct FixedClk: Clock {
        let millis: Int64
        func nowMillis() -> Int64 { millis }
    }

    /// A scriptable `TrustCore` with no native dependency.
    private final class FakeTrustCore: TrustCore {
        var intervalSecs: UInt32
        var level: TrustLevel
        var decisionValue: TrustDecision
        var killed = false
        var applyResult = false
        var loadConfigCount = 0

        init(intervalSecs: UInt32 = 0, level: TrustLevel = .trusted, decisionValue: TrustDecision = .allow) {
            self.intervalSecs = intervalSecs
            self.level = level
            self.decisionValue = decisionValue
        }

        var version: String { "fake-core" }
        func loadConfig(_ signedConfigBytes: Data) throws {}
        func tryLoadConfig(_ signedConfigBytes: Data) -> Bool { loadConfigCount += 1; return true }
        func evaluateRisk(_ riskBits: UInt64) throws -> CoreRiskScore {
            CoreRiskScore(score: UInt32(truncatingIfNeeded: riskBits), confidence: .high)
        }
        func computeRiskLevel(_ riskBits: UInt64) -> TrustLevel { level }
        func evaluateRiskAndLevel(_ riskBits: UInt64) throws -> (CoreRiskScore, TrustLevel) {
            (CoreRiskScore(score: UInt32(truncatingIfNeeded: riskBits), confidence: .high), level)
        }
        func createEvent(
            eventType: EventType, riskBits: UInt64, confidence: Confidence, buildHash: String,
            policyHash: String, installKeyHash: String, coarseTimeBucket: Int64, country: String?
        ) throws -> Data { Data() }
        func batchAndCompress(_ events: [Data]) throws -> Data { Data() }
        func generateRequestProof(tokenId: String, requestHash: Data, nonce: Data, sequence: Int64) throws -> Data { Data() }
        func generateNonce(_ length: Int) throws -> Data { Data(count: length) }
        func compress(_ data: Data, level: Int32) throws -> Data { data }
        func decompress(_ data: Data) throws -> Data { data }
        func reattestIntervalSecs() -> UInt32 { intervalSecs }
        func decision(_ riskBits: UInt64) -> TrustDecision { decisionValue }
        func decisionWithLevel(_ riskBits: UInt64) -> (TrustLevel, TrustDecision) { (level, decisionValue) }
        func applyKillSwitch(_ signedKillSwitchBytes: Data) -> Bool { killed = applyResult; return killed }
        func isKilled() -> Bool { killed }
    }

    /// Records fetch calls so escalation can be observed.
    private final class CountingConfigProvider: ConfigProvider {
        var fetchConfigCount = 0
        var fetchKillSwitchCount = 0
        let config: Data?
        let killSwitch: Data?

        init(config: Data? = Data([1, 2, 3, 4]), killSwitch: Data? = nil) {
            self.config = config
            self.killSwitch = killSwitch
        }
        func cachedConfig() -> Data? { config }
        func fetchConfig() -> Data? { fetchConfigCount += 1; return config }
        func persist(_ config: Data) {}
        func fetchKillSwitch() -> Data? { fetchKillSwitchCount += 1; return killSwitch }
    }

    private func makeSDK(_ core: TrustCore, _ provider: ConfigProvider = CountingConfigProvider()) -> KsealDesktop {
        KsealDesktop(
            core: core,
            env: FakeDesktopEnvironment(),
            options: KsealDesktopOptions(),
            configProvider: provider,
            telemetrySink: BufferingTelemetrySink(),
            attestor: LocalCodeIntegrityAttestor(),
            installIdentityHash: "deadbeef",
            clock: FixedClk(millis: 1_700_000_000_000)
        )
    }

    // MARK: - Deterministic wiring (fake core)

    func testContinuousModeOffByDefault() {
        let sdk = makeSDK(FakeTrustCore(intervalSecs: 0))
        XCTAssertEqual(sdk.reattestIntervalSecs, 0)
        XCTAssertFalse(sdk.startContinuousProtection())
    }

    func testReattestCycleDispatchesTrustDecision() {
        let sdk = makeSDK(FakeTrustCore(level: .highRisk, decisionValue: .deny))
        var seen: (TrustLevel, TrustDecision)?
        sdk.onTrustDecision = { level, decision in seen = (level, decision) }

        sdk.runReattestCycle()

        XCTAssertEqual(seen?.0, .highRisk)
        XCTAssertEqual(seen?.1, .deny)
    }

    func testStepUpDecisionIsSurfaced() throws {
        let sdk = makeSDK(FakeTrustCore(level: .mediumRisk, decisionValue: .stepUp))
        let (level, decision) = try sdk.evaluateTrustDecision()
        XCTAssertEqual(level, .mediumRisk)
        XCTAssertEqual(decision, .stepUp)
    }

    func testReattestCycleAlwaysPullsKillSwitch() {
        let trustedProvider = CountingConfigProvider()
        makeSDK(FakeTrustCore(level: .trusted, decisionValue: .allow), trustedProvider).runReattestCycle()
        XCTAssertEqual(trustedProvider.fetchKillSwitchCount, 1)

        let riskyProvider = CountingConfigProvider(killSwitch: Data(count: 8))
        makeSDK(FakeTrustCore(level: .highRisk, decisionValue: .deny), riskyProvider).runReattestCycle()
        XCTAssertEqual(riskyProvider.fetchKillSwitchCount, 1)
    }

    func testAuthorizeRequestSurfacesServerDecision() throws {
        let core = FakeTrustCore(level: .highRisk, decisionValue: .allow)
        let sdk = makeSDK(core)
        sdk.setTrustToken("token-1")
        var seen: TrustDecision?
        sdk.onTrustDecision = { _, decision in seen = decision }

        let client = FakeTrustSessionClient()
        client.decision = RequestProofDecision(decision: .deny, reason: "high risk")
        let result = try sdk.authorizeRequest(requestHash: Data(count: 32), using: client)

        XCTAssertEqual(result.decision, .deny)
        XCTAssertEqual(seen, .deny) // server decision, not the local core's
    }

    func testDefaultTrustDecisionListenerIsNoOp() {
        let sdk = makeSDK(FakeTrustCore(level: .critical, decisionValue: .deny))
        XCTAssertNil(sdk.onTrustDecision)
        sdk.runReattestCycle() // must not throw or act on its own
    }

    // MARK: - End-to-end kill switch (real Rust core via FFI)

    // Ed25519 public key matching the signatures below (SigningKey [1u8; 32]).
    private let killSwitchPublicKey = Data([
        138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114,
        202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
    ])
    // Serialized kseal.v1.SignedKillSwitch (tenant/app/build "tenant"/"app"/"build").
    private let disableBytes = Data([
        10, 6, 116, 101, 110, 97, 110, 116, 18, 3, 97, 112, 112, 26, 5, 98, 117,
        105, 108, 100, 32, 2, 40, 3, 48, 128, 226, 207, 170, 6, 58, 4, 116, 101, 115,
        116, 66, 64, 233, 245, 127, 121, 34, 207, 22, 43, 23, 99, 216, 51, 31, 142, 181,
        228, 170, 113, 223, 103, 36, 70, 161, 22, 116, 249, 126, 157, 51, 114, 143, 131,
        188, 124, 114, 224, 238, 15, 158, 166, 13, 67, 243, 22, 49, 34, 209, 170, 71,
        50, 21, 190, 155, 85, 73, 191, 165, 159, 127, 148, 218, 142, 121, 9, 74, 2, 107,
        49,
    ])
    private let enableBytes = Data([
        10, 6, 116, 101, 110, 97, 110, 116, 18, 3, 97, 112, 112, 26, 5, 98, 117,
        105, 108, 100, 32, 1, 40, 3, 48, 128, 226, 207, 170, 6, 58, 4, 116, 101, 115, 116,
        66, 64, 33, 220, 104, 59, 216, 149, 67, 206, 248, 63, 146, 80, 121, 136, 16,
        114, 55, 222, 164, 2, 212, 66, 129, 74, 214, 200, 124, 14, 48, 22, 36, 21, 71,
        149, 165, 159, 220, 2, 167, 229, 223, 251, 249, 242, 91, 135, 251, 52, 14, 191,
        20, 209, 33, 99, 233, 114, 12, 48, 158, 11, 86, 170, 102, 15, 74, 2, 107, 49,
    ])
    // A DISABLE signed by a different key (attacker [2u8; 32]).
    private let forgedDisableBytes = Data([
        10, 6, 116, 101, 110, 97, 110, 116, 18, 3, 97, 112, 112, 26, 5, 98, 117,
        105, 108, 100, 32, 2, 40, 3, 48, 128, 226, 207, 170, 6, 58, 4, 116, 101, 115, 116,
        66, 64, 67, 231, 121, 10, 254, 116, 4, 76, 11, 173, 239, 63, 66, 11, 150, 130,
        83, 249, 76, 248, 219, 36, 222, 252, 182, 19, 47, 49, 237, 12, 61, 36, 107, 186,
        108, 41, 244, 74, 11, 162, 174, 46, 190, 173, 109, 242, 201, 248, 0, 224, 194,
        34, 119, 210, 51, 217, 58, 246, 19, 63, 12, 246, 185, 7, 74, 2, 107, 49,
    ])

    private func makeRealCoreSDK(provider: ConfigProvider) throws -> KsealDesktop {
        let core = try NativeTrustCore.create(
            configPublicKey: killSwitchPublicKey,
            proofKey: Data("instance-key".utf8),
            platform: .desktopMac
        )
        return KsealDesktop(
            core: core,
            env: FakeDesktopEnvironment(),
            options: KsealDesktopOptions(),
            configProvider: provider,
            telemetrySink: BufferingTelemetrySink(),
            attestor: LocalCodeIntegrityAttestor(),
            installIdentityHash: "deadbeef",
            clock: FixedClk(millis: 1_700_000_000_000)
        )
    }

    func testValidKillSwitchDrivesSDKIntoDegradedState() throws {
        let sdk = try makeRealCoreSDK(provider: CountingConfigProvider())
        var transitions: [Bool] = []
        sdk.onKillSwitchChanged = { transitions.append($0) }

        XCTAssertFalse(sdk.isKilled)
        XCTAssertTrue(sdk.applyKillSwitch(disableBytes))
        XCTAssertTrue(sdk.isKilled)

        // A validly-signed ENABLE lifts the kill (server re-enable).
        XCTAssertFalse(sdk.applyKillSwitch(enableBytes))
        XCTAssertFalse(sdk.isKilled)
        XCTAssertEqual(transitions, [true, false])
    }

    func testForgedKillSwitchNeverDisablesApp() throws {
        let sdk = try makeRealCoreSDK(provider: CountingConfigProvider())
        var fired = false
        sdk.onKillSwitchChanged = { _ in fired = true }

        XCTAssertFalse(sdk.applyKillSwitch(forgedDisableBytes))
        XCTAssertFalse(sdk.isKilled)
        XCTAssertFalse(fired)
    }

    func testRefreshKillSwitchAppliesProviderBytes() throws {
        let provider = CountingConfigProvider(killSwitch: disableBytes)
        let sdk = try makeRealCoreSDK(provider: provider)
        XCTAssertTrue(sdk.refreshKillSwitch())
        XCTAssertTrue(sdk.isKilled)
        XCTAssertEqual(provider.fetchKillSwitchCount, 1)
    }
}
