import XCTest
@testable import KsealSDK

/// Exercises the screen-capture detection rule directly. The decision logic
/// lives in the pure `ScreenCaptureMonitor.assess(isCaptured:screenshotObserved:)`
/// so it is deterministic on any host; the `UIScreen`/notification plumbing is a
/// thin adapter that feeds it on a real device.
final class ScreenCaptureDetectorTests: XCTestCase {

    override func setUp() {
        super.setUp()
        ScreenCaptureMonitor.shared.clearScreenshotObservation()
    }

    override func tearDown() {
        ScreenCaptureMonitor.shared.clearScreenshotObservation()
        super.tearDown()
    }

    func testProbeIdIsStable() {
        XCTAssertEqual(ScreenCaptureDetector().id, "screen_capture")
    }

    func testCleanStateIsEmpty() {
        XCTAssertTrue(ScreenCaptureMonitor.assess(isCaptured: false, screenshotObserved: false).isEmpty)
    }

    func testActiveCaptureIsScreenCapture() {
        XCTAssertEqual(
            ScreenCaptureMonitor.assess(isCaptured: true, screenshotObserved: false),
            [.screenCapture]
        )
    }

    func testScreenshotObservationIsScreenCapture() {
        XCTAssertEqual(
            ScreenCaptureMonitor.assess(isCaptured: false, screenshotObserved: true),
            [.screenCapture]
        )
    }

    func testCaptureAndScreenshotIsScreenCapture() {
        XCTAssertTrue(
            ScreenCaptureMonitor.assess(isCaptured: true, screenshotObserved: true)
                .contains(.screenCapture)
        )
    }

    func testNoCaptureNoScreenshotIsCleanThroughDetector() {
        // On the test host UIKit is unavailable, so isCaptured is false; with no
        // screenshot observed the probe must report nothing.
        XCTAssertTrue(ScreenCaptureDetector().evaluate().isEmpty)
    }

    func testLatchedScreenshotFlagsThroughMonitor() {
        ScreenCaptureMonitor.shared.recordScreenshot()
        XCTAssertTrue(ScreenCaptureMonitor.shared.hasObservedScreenshot())
        XCTAssertTrue(ScreenCaptureMonitor.shared.evaluate().contains(.screenCapture))

        ScreenCaptureMonitor.shared.clearScreenshotObservation()
        XCTAssertFalse(ScreenCaptureMonitor.shared.hasObservedScreenshot())
        XCTAssertTrue(ScreenCaptureMonitor.shared.evaluate().isEmpty)
    }
}
