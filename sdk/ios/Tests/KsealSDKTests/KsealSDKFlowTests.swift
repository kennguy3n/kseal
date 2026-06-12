import XCTest
@testable import KsealSDK

private struct FixedClock: Clock {
    let millis: Int64
    func nowMillis() -> Int64 { millis }
}

/// End-to-end SDK flow against the REAL Rust core with a controlled device
/// environment and an in-memory telemetry sink (no network, no device).
final class KsealSDKFlowTests: XCTestCase {

    private func makeSDK(
        env: DeviceEnvironment = FakeDeviceEnvironment(),
        sink: BufferingTelemetrySink = BufferingTelemetrySink(),
        maxBatchEvents: Int = 32
    ) throws -> KsealSDK {
        let core = try NativeTrustCore.create(
            configPublicKey: Data(repeating: 7, count: 32),
            proofKey: Data("instance-key".utf8),
            platform: .ios
        )
        return KsealSDK(
            tenantId: "tenant-1",
            appId: "com.example.app",
            apiKey: "api-key",
            core: core,
            env: env,
            options: KsealOptions(maxBatchEvents: maxBatchEvents),
            configProvider: FileConfigProvider(directory: FileManager.default.temporaryDirectory),
            telemetrySink: sink,
            installIdentityHash: "deadbeef",
            clock: FixedClock(millis: 1_700_000_000_000)
        )
    }

    func testCleanDeviceEvaluatesToNoSignals() throws {
        let assessment = try makeSDK().evaluateRisk()
        XCTAssertTrue(assessment.isClean)
        XCTAssertEqual(assessment.score, 0)
        XCTAssertEqual(assessment.confidence, .high)
        XCTAssertTrue(assessment.signals.isEmpty)
    }

    func testCompromisedDeviceSurfacesSignalsAndScore() throws {
        let env = FakeDeviceEnvironment()
        env.existingFiles.insert("/Applications/Cydia.app")
        env.traced = true
        let assessment = try makeSDK(env: env).evaluateRisk()
        XCTAssertTrue(assessment.signals.contains(.jailbreak))
        XCTAssertTrue(assessment.signals.contains(.debugger))
        XCTAssertGreaterThan(assessment.score, 0)
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

    func testFlushWithNoEventsEmitsNothing() throws {
        let sink = BufferingTelemetrySink()
        let sdk = try makeSDK(sink: sink)
        sdk.flushTelemetry()
        XCTAssertTrue(sink.drain().isEmpty)
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
