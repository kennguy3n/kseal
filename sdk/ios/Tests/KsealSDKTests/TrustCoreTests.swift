import XCTest
@testable import KsealSDK

/// Exercises the REAL Rust trust core through the C ABI on the host.
///
/// The static archive `libkseal_ffi.a` is built by `scripts/build-rust-host.sh`
/// and linked by `Package.swift`. This is not a mock — it is the same `kseal_*`
/// C ABI the iOS xcframework ships, validating the FFI integration end to end.
final class TrustCoreTests: XCTestCase {

    private func makeCore() throws -> NativeTrustCore {
        try NativeTrustCore.create(
            configPublicKey: Data(repeating: 7, count: 32),
            proofKey: Data("instance-key".utf8),
            platform: .ios
        )
    }

    func testVersionIsNonEmpty() throws {
        XCTAssertFalse(try makeCore().version.isEmpty)
    }

    func testNonceHasRequestedLengthAndIsRandom() throws {
        let core = try makeCore()
        let n1 = try core.generateNonce(16)
        let n2 = try core.generateNonce(16)
        XCTAssertEqual(n1.count, 16)
        XCTAssertNotEqual(n1, n2)
    }

    func testCompressDecompressRoundTrips() throws {
        let core = try makeCore()
        let data = Data("kseal ".utf8).reduce(into: Data()) { acc, _ in acc.append(Data("kseal ".utf8)) }
        let payload = Data(repeating: 0x41, count: 512)
        let compressed = try core.compress(payload, level: 0)
        XCTAssertFalse(compressed.isEmpty)
        XCTAssertEqual(try core.decompress(compressed), payload)
        _ = data
    }

    /// With no policy loaded the core uses the default per-signal weight (10).
    func testEvaluateRiskUsesDefaultWeights() throws {
        let core = try makeCore()
        let bits = RiskSignal.pack([.jailbreak, .debugger])
        let score = try core.evaluateRisk(bits)
        XCTAssertEqual(score.score, 20)
        XCTAssertEqual(score.confidence, .medium)
    }

    func testCleanBitsScoreZero() throws {
        let core = try makeCore()
        let score = try core.evaluateRisk(0)
        XCTAssertEqual(score.score, 0)
        XCTAssertEqual(score.confidence, .high)
    }

    func testTrustLevelUnspecifiedWithoutPolicy() throws {
        let core = try makeCore()
        XCTAssertEqual(core.computeRiskLevel(RiskSignal.jailbreak.mask), .unspecified)
    }

    func testCreateEventAndBatchProduceWire() throws {
        let core = try makeCore()
        let event = try core.createEvent(
            eventType: .rootRisk,
            riskBits: RiskSignal.jailbreak.mask,
            confidence: .low,
            buildHash: "build",
            policyHash: "policy",
            installKeyHash: "install",
            coarseTimeBucket: 1_700_000_000,
            country: nil
        )
        XCTAssertFalse(event.isEmpty)
        XCTAssertFalse(try core.batchAndCompress([event]).isEmpty)
    }

    func testRequestProofIsDeterministic() throws {
        let core = try makeCore()
        let hash = Data((0..<32).map { UInt8($0) })
        let nonce = Data(repeating: 9, count: 16)
        let p1 = try core.generateRequestProof(tokenId: "tok-1", requestHash: hash, nonce: nonce, sequence: 7)
        let p2 = try core.generateRequestProof(tokenId: "tok-1", requestHash: hash, nonce: nonce, sequence: 7)
        XCTAssertFalse(p1.isEmpty)
        XCTAssertEqual(p1, p2)
        let p3 = try core.generateRequestProof(tokenId: "tok-1", requestHash: hash, nonce: nonce, sequence: 8)
        XCTAssertNotEqual(p1, p3)
    }

    func testVerifyConfigSignatureRejectsGarbage() {
        let verified = verifyConfigSignature(
            config: Data("config".utf8),
            signature: Data(repeating: 0, count: 64),
            publicKey: Data(repeating: 7, count: 32)
        )
        XCTAssertFalse(verified)
    }

    func testLoadGarbageConfigFails() throws {
        let core = try makeCore()
        XCTAssertFalse(core.tryLoadConfig(Data([1, 2, 3, 4])))
    }

    func testCreateWithEmptyKeysSucceedsWithDefaults() throws {
        // Empty keys are accepted by the core (it derives/falls back); should not crash.
        let core = try NativeTrustCore.create(configPublicKey: Data(), proofKey: Data(), platform: .ios)
        XCTAssertFalse(core.version.isEmpty)
    }
}
