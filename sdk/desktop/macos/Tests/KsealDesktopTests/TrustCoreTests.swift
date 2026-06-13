import XCTest
@testable import KsealDesktop

/// Exercises the REAL Rust trust core through the C ABI on the host.
///
/// The shared library `libkseal_ffi.{so,dylib}` is built by
/// `scripts/build-rust-host.sh` and linked by `Package.swift`. This is not a
/// mock — it is the same `kseal_*` C ABI the desktop SDK ships, validating the
/// FFI integration end to end.
final class TrustCoreTests: XCTestCase {

    private func makeCore() throws -> NativeTrustCore {
        try NativeTrustCore.create(
            configPublicKey: Data(repeating: 7, count: 32),
            proofKey: Data("instance-key".utf8),
            platform: .desktopMac
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
        let payload = Data(repeating: 0x41, count: 512)
        let compressed = try core.compress(payload, level: 0)
        XCTAssertFalse(compressed.isEmpty)
        XCTAssertEqual(try core.decompress(compressed), payload)
    }

    func testEvaluateRiskUsesDefaultWeights() throws {
        let core = try makeCore()
        let bits = RiskSignal.pack([.tamper, .hooking])
        let score = try core.evaluateRisk(bits)
        XCTAssertEqual(score.score, 20) // default per-signal weight of 10
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
        XCTAssertEqual(core.computeRiskLevel(RiskSignal.tamper.mask), .unspecified)
    }

    func testCreateEventAndBatchProduceWire() throws {
        let core = try makeCore()
        let event = try core.createEvent(
            eventType: .appIntegrityFail,
            riskBits: RiskSignal.appIntegrity.mask,
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

    func testRequestProofIsDeterministicAndSequenceSensitive() throws {
        let core = try makeCore()
        let hash = Data((0..<32).map { UInt8($0) })
        let nonce = Data(repeating: 9, count: 16)
        let p1 = try core.generateRequestProof(tokenId: "tok-1", requestHash: hash, nonce: nonce, sequence: 7)
        let p2 = try core.generateRequestProof(tokenId: "tok-1", requestHash: hash, nonce: nonce, sequence: 7)
        let p3 = try core.generateRequestProof(tokenId: "tok-1", requestHash: hash, nonce: nonce, sequence: 8)
        XCTAssertFalse(p1.isEmpty)
        XCTAssertEqual(p1, p2)
        XCTAssertNotEqual(p1, p3)
    }
}
