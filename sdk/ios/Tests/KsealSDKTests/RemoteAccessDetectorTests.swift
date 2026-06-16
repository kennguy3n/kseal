import XCTest
@testable import KsealSDK

final class RemoteAccessDetectorTests: XCTestCase {
    func testNotCapturedIsClean() {
        let probe = RemoteAccessDetector(isScreenCaptured: { false })
        XCTAssertTrue(probe.evaluate().isEmpty)
    }

    func testCapturedIsRemoteAccess() {
        let probe = RemoteAccessDetector(isScreenCaptured: { true })
        XCTAssertEqual(probe.evaluate(), [.remoteAccess])
    }

    func testDefaultInitIsCleanWhereUIKitUnavailable() {
        // The default initializer reads `UIScreen.main.isCaptured`, which is
        // unavailable (and therefore reports `false`) on non-iOS hosts such as
        // the macOS / Linux test runners used by CI.
        #if !canImport(UIKit)
        XCTAssertTrue(RemoteAccessDetector().evaluate().isEmpty)
        #endif
    }
}
