import XCTest
@testable import KsealDesktop

private struct FixedClock: Clock {
    let millis: Int64
    func nowMillis() -> Int64 { millis }
}

/// End-to-end SDK flow against the REAL Rust core with a controlled desktop
/// environment, a fake trust-session client, and an in-memory telemetry sink
/// (no network, no device).
final class KsealDesktopFlowTests: XCTestCase {

    private func makeSDK(
        env: DesktopEnvironment = FakeDesktopEnvironment(),
        sink: BufferingTelemetrySink = BufferingTelemetrySink(),
        attestor: CodeIntegrityAttestor = LocalCodeIntegrityAttestor(),
        maxBatchEvents: Int = 32
    ) throws -> KsealDesktop {
        let policy = DesktopIntegrityPolicy(
            expectedTeamIdentifier: "ABCDE12345",
            expectedSigningIdentifier: "com.example.app"
        )
        let core = try NativeTrustCore.create(
            configPublicKey: Data(repeating: 7, count: 32),
            proofKey: Data("instance-key".utf8),
            platform: .desktopMac
        )
        return KsealDesktop(
            core: core,
            env: env,
            options: KsealDesktopOptions(integrityPolicy: policy, maxBatchEvents: maxBatchEvents),
            configProvider: FileConfigProvider(directory: FileManager.default.temporaryDirectory),
            telemetrySink: sink,
            attestor: attestor,
            installIdentityHash: "deadbeef",
            clock: FixedClock(millis: 1_700_000_000_000)
        )
    }

    func testCleanSignedAppEvaluatesToNoSignals() throws {
        let assessment = try makeSDK().evaluateRisk()
        XCTAssertTrue(assessment.isClean)
        XCTAssertEqual(assessment.score, 0)
        XCTAssertEqual(assessment.confidence, .high)
        XCTAssertTrue(assessment.signals.isEmpty)
    }

    func testTamperedAppSurfacesSignalsAndScore() throws {
        let env = FakeDesktopEnvironment()
        env.signing.signatureValid = false
        env.environment["DYLD_INSERT_LIBRARIES"] = "/tmp/evil.dylib"
        let assessment = try makeSDK(env: env).evaluateRisk()
        XCTAssertTrue(assessment.signals.contains(.tamper))
        XCTAssertTrue(assessment.signals.contains(.hooking))
        XCTAssertGreaterThan(assessment.score, 0)
    }

    func testDebuggerProbeOffByDefault() throws {
        let env = FakeDesktopEnvironment()
        env.traced = true
        // Default probe set omits the debugger probe (desktop caution).
        let assessment = try makeSDK(env: env).evaluateRisk()
        XCTAssertFalse(assessment.signals.contains(.debugger))
    }

    func testRequestProofRequiresTrustToken() throws {
        let sdk = try makeSDK()
        XCTAssertThrowsError(try sdk.getRequestProof(requestHash: Data(repeating: 1, count: 32)))
    }

    func testRequestProofBindsTokenAndIncrementsSequence() throws {
        let sdk = try makeSDK()
        sdk.setTrustToken("token-xyz")
        let hash = Data(repeating: 2, count: 32)
        let p1 = try sdk.getRequestProof(requestHash: hash)
        let p2 = try sdk.getRequestProof(requestHash: hash)
        XCTAssertEqual(p1.tokenId, "token-xyz")
        XCTAssertEqual(p1.sequence, 1)
        XCTAssertEqual(p2.sequence, 2)
        XCTAssertFalse(p1.proofBytes.isEmpty)
        XCTAssertEqual(p1.nonce.count, 16)
    }

    func testEstablishTrustSessionStoresToken() throws {
        let sdk = try makeSDK()
        let fake = FakeTrustSessionClient()
        fake.session = TrustSession(
            tokenId: "tok-100", signedToken: Data([1, 2, 3]), accepted: true,
            rejectionReason: "", expiresAt: 1_700_000_999, riskLevel: .trusted, capabilityScopes: ["api:read"]
        )
        let session = try sdk.establishTrustSession(using: fake)
        XCTAssertTrue(session.accepted)
        XCTAssertEqual(fake.lastInstanceId, "deadbeef")
        // Token is now set: a request proof can be produced.
        let proof = try sdk.getRequestProof(requestHash: Data(repeating: 5, count: 32))
        XCTAssertEqual(proof.tokenId, "tok-100")
    }

    func testRejectedSessionDoesNotSetToken() throws {
        let sdk = try makeSDK()
        let fake = FakeTrustSessionClient()
        fake.session = TrustSession(
            tokenId: "", signedToken: Data(), accepted: false,
            rejectionReason: "risk too high", expiresAt: 0, riskLevel: .critical, capabilityScopes: []
        )
        _ = try sdk.establishTrustSession(using: fake)
        XCTAssertThrowsError(try sdk.getRequestProof(requestHash: Data(repeating: 5, count: 32)))
    }

    func testAuthorizeRequestRoundTrips() throws {
        let sdk = try makeSDK()
        sdk.setTrustToken("tok-1")
        let fake = FakeTrustSessionClient()
        fake.decision = RequestProofDecision(decision: .allow, reason: "ok")
        let decision = try sdk.authorizeRequest(requestHash: Data(repeating: 3, count: 32), using: fake)
        XCTAssertEqual(decision.decision, .allow)
        XCTAssertNotNil(fake.lastProof)
    }

    func testReportEventBuffersUntilBatchThreshold() throws {
        let sink = BufferingTelemetrySink()
        let sdk = try makeSDK(sink: sink, maxBatchEvents: 3)
        sdk.reportEvent(.policyDecision)
        sdk.reportEvent(.policyDecision)
        XCTAssertTrue(sink.drain().isEmpty)
        sdk.reportEvent(.policyDecision)
        XCTAssertEqual(sink.drain().count, 1)
    }

    func testFlushTelemetryEmitsBufferedEvents() throws {
        let sink = BufferingTelemetrySink()
        let sdk = try makeSDK(sink: sink, maxBatchEvents: 100)
        sdk.reportEvent(.policyDecision)
        sdk.flushTelemetry()
        XCTAssertEqual(sink.drain().count, 1)
    }

    func testPinningFailureEmitsImmediateEvent() throws {
        let sink = BufferingTelemetrySink()
        let sdk = try makeSDK(sink: sink)
        sdk.reportPinningFailure()
        XCTAssertEqual(sink.drain().count, 1)
    }

    func testCoreVersionExposed() throws {
        XCTAssertFalse(try makeSDK().coreVersion.isEmpty)
    }
}
