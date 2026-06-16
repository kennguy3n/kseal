import XCTest
@testable import KsealSDK

/// Phase 3 continuous-protection / active-response wiring, driven against a
/// `FakeTrustCore` so the re-attestation cycle, `onTrustDecision` dispatch, and
/// kill-switch surfacing are exercised deterministically without the native
/// library or Ed25519 signing. The authoritative crypto / decision / kill-switch
/// semantics are pinned by the Rust core + FFI tests (which run in CI).
final class ContinuousProtectionTests: XCTestCase {

    private struct FixedClock: Clock {
        let millis: Int64
        func nowMillis() -> Int64 { millis }
    }

    /// A scriptable `TrustCore` with no native dependency.
    private final class FakeTrustCore: TrustCore {
        var intervalSecs: UInt32
        var level: TrustLevel
        var decisionValue: Decision
        var killed = false
        var applyResult = false
        var loadConfigCount = 0

        init(intervalSecs: UInt32 = 0, level: TrustLevel = .trusted, decisionValue: Decision = .allow) {
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
        func decision(_ riskBits: UInt64) -> Decision { decisionValue }
        func decisionWithLevel(_ riskBits: UInt64) -> (TrustLevel, Decision) { (level, decisionValue) }
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

    private func makeSDK(_ core: FakeTrustCore, _ provider: ConfigProvider = CountingConfigProvider()) -> KsealSDK {
        KsealSDK(
            tenantId: "tenant-a",
            appId: "com.example.app",
            apiKey: "api-key",
            core: core,
            env: FakeDeviceEnvironment(),
            options: KsealOptions(),
            configProvider: provider,
            telemetrySink: BufferingTelemetrySink(),
            installIdentityHash: "deadbeef",
            clock: FixedClock(millis: 1_700_000_000_000)
        )
    }

    func testContinuousModeOffByDefault() {
        let core = FakeTrustCore(intervalSecs: 0)
        let sdk = makeSDK(core)
        XCTAssertEqual(sdk.reattestIntervalSecs, 0)
        XCTAssertFalse(sdk.startContinuousProtection())
    }

    func testReattestCycleDispatchesTrustDecision() {
        let core = FakeTrustCore(level: .highRisk, decisionValue: .deny)
        let sdk = makeSDK(core)
        var seen: (TrustLevel, Decision)?
        sdk.onTrustDecision = { level, decision in seen = (level, decision) }

        sdk.runReattestCycle()

        XCTAssertEqual(seen?.0, .highRisk)
        XCTAssertEqual(seen?.1, .deny)
    }

    func testStepUpDecisionIsSurfaced() throws {
        let core = FakeTrustCore(level: .mediumRisk, decisionValue: .stepUp)
        let sdk = makeSDK(core)
        let (level, decision) = try sdk.evaluateTrustDecision()
        XCTAssertEqual(level, .mediumRisk)
        XCTAssertEqual(decision, .stepUp)
    }

    func testEscalationPullsKillSwitchOnlyWhenRiskElevated() {
        let trustedProvider = CountingConfigProvider()
        makeSDK(FakeTrustCore(level: .trusted, decisionValue: .allow), trustedProvider).runReattestCycle()
        XCTAssertEqual(trustedProvider.fetchKillSwitchCount, 0)

        let riskyProvider = CountingConfigProvider(killSwitch: Data(count: 8))
        makeSDK(FakeTrustCore(level: .highRisk, decisionValue: .deny), riskyProvider).runReattestCycle()
        XCTAssertEqual(riskyProvider.fetchKillSwitchCount, 1)
    }

    func testKillSwitchSurfacingFiresOnTransition() {
        let core = FakeTrustCore()
        core.applyResult = true
        let sdk = makeSDK(core)
        var lastState: Bool?
        sdk.onKillSwitchChanged = { lastState = $0 }

        XCTAssertFalse(sdk.isKilled)
        XCTAssertTrue(sdk.applyKillSwitch(Data(count: 16)))
        XCTAssertTrue(sdk.isKilled)
        XCTAssertEqual(lastState, true)
    }

    func testKillSwitchListenerNotFiredWithoutTransition() {
        let core = FakeTrustCore()
        core.applyResult = false
        let sdk = makeSDK(core)
        var fired = false
        sdk.onKillSwitchChanged = { _ in fired = true }

        XCTAssertFalse(sdk.applyKillSwitch(Data(count: 16)))
        XCTAssertFalse(fired)
        XCTAssertFalse(sdk.isKilled)
    }

    func testRefreshKillSwitchIsNoOpWhenProviderHasNone() {
        let provider = CountingConfigProvider(killSwitch: nil)
        let sdk = makeSDK(FakeTrustCore(), provider)
        var fired = false
        sdk.onKillSwitchChanged = { _ in fired = true }

        XCTAssertFalse(sdk.refreshKillSwitch())
        XCTAssertEqual(provider.fetchKillSwitchCount, 1)
        XCTAssertFalse(fired)
    }

    func testDefaultTrustDecisionListenerIsNoOp() {
        let sdk = makeSDK(FakeTrustCore(level: .critical, decisionValue: .deny))
        XCTAssertNil(sdk.onTrustDecision)
        sdk.runReattestCycle() // must not throw or act on its own
    }
}
