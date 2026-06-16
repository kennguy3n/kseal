import XCTest
@testable import KsealSDK

final class RiskSignalTests: XCTestCase {

    /// Bit indices must mirror the Rust core's RiskBitset exactly.
    func testBitLayoutMatchesRustCore() {
        XCTAssertEqual(RiskSignal.root.rawValue, 0)
        XCTAssertEqual(RiskSignal.jailbreak.rawValue, 1)
        XCTAssertEqual(RiskSignal.emulator.rawValue, 2)
        XCTAssertEqual(RiskSignal.simulator.rawValue, 3)
        XCTAssertEqual(RiskSignal.debugger.rawValue, 4)
        XCTAssertEqual(RiskSignal.hooking.rawValue, 5)
        XCTAssertEqual(RiskSignal.tamper.rawValue, 6)
        XCTAssertEqual(RiskSignal.appIntegrity.rawValue, 7)
        XCTAssertEqual(RiskSignal.networkMitm.rawValue, 8)
        XCTAssertEqual(RiskSignal.environment.rawValue, 9)
        XCTAssertEqual(RiskSignal.proxy.rawValue, 10)
        XCTAssertEqual(RiskSignal.userCa.rawValue, 11)
        XCTAssertEqual(RiskSignal.pinningFailure.rawValue, 12)
        XCTAssertEqual(RiskSignal.attestationFail.rawValue, 13)
        XCTAssertEqual(RiskSignal.secureHwMissing.rawValue, 14)
        XCTAssertEqual(RiskSignal.repackaged.rawValue, 15)
        XCTAssertEqual(RiskSignal.screenCapture.rawValue, 16)
        XCTAssertEqual(RiskSignal.overlayAbuse.rawValue, 17)
        XCTAssertEqual(RiskSignal.accessibilityAbuse.rawValue, 18)
        XCTAssertEqual(RiskSignal.maliciousIme.rawValue, 19)
        XCTAssertEqual(RiskSignal.remoteAccess.rawValue, 20)
    }

    func testPackUnpackRoundTrip() {
        let signals: Set<RiskSignal> = [.jailbreak, .debugger, .proxy]
        let bits = RiskSignal.pack(signals)
        XCTAssertEqual(bits, (UInt64(1) << 1) | (UInt64(1) << 4) | (UInt64(1) << 10))
        XCTAssertEqual(RiskSignal.unpack(bits), signals)
    }

    func testEmptyPacksToZero() {
        XCTAssertEqual(RiskSignal.pack([]), 0)
        XCTAssertEqual(RiskSignal.unpack(0), [])
    }
}
