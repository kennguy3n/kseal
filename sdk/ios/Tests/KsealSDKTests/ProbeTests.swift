import XCTest
@testable import KsealSDK

final class JailbreakDetectorTests: XCTestCase {
    func testCleanDeviceIsClean() {
        XCTAssertTrue(JailbreakDetector(FakeDeviceEnvironment()).evaluate().isEmpty)
    }

    func testCydiaArtifactIsJailbreak() {
        let env = FakeDeviceEnvironment()
        env.existingFiles.insert("/Applications/Cydia.app")
        XCTAssertTrue(JailbreakDetector(env).evaluate().contains(.jailbreak))
    }

    func testMobileSubstrateIsJailbreak() {
        let env = FakeDeviceEnvironment()
        env.existingFiles.insert("/Library/MobileSubstrate/MobileSubstrate.dylib")
        XCTAssertTrue(JailbreakDetector(env).evaluate().contains(.jailbreak))
    }

    func testSandboxEscapeIsJailbreak() {
        let env = FakeDeviceEnvironment()
        env.canWriteOutside = true
        XCTAssertTrue(JailbreakDetector(env).evaluate().contains(.jailbreak))
    }

    func testRelinkedApplicationsIsJailbreak() {
        let env = FakeDeviceEnvironment()
        env.symlinks.insert("/Applications")
        XCTAssertTrue(JailbreakDetector(env).evaluate().contains(.jailbreak))
    }

    func testDyldInsertIsEnvironmentRisk() {
        let env = FakeDeviceEnvironment()
        env.environment["DYLD_INSERT_LIBRARIES"] = "/tmp/evil.dylib"
        XCTAssertTrue(JailbreakDetector(env).evaluate().contains(.environment))
    }
}

final class SimulatorDetectorTests: XCTestCase {
    func testPhysicalDeviceIsClean() {
        XCTAssertTrue(SimulatorDetector(FakeDeviceEnvironment()).evaluate().isEmpty)
    }

    func testSimulatorBuildIsSimulator() {
        let env = FakeDeviceEnvironment()
        env.simulator = true
        let signals = SimulatorDetector(env).evaluate()
        XCTAssertTrue(signals.contains(.simulator))
        XCTAssertTrue(signals.contains(.environment))
    }

    func testSimulatorEnvVarIsSimulator() {
        let env = FakeDeviceEnvironment()
        env.environment["SIMULATOR_DEVICE_NAME"] = "iPhone 15"
        XCTAssertTrue(SimulatorDetector(env).evaluate().contains(.simulator))
    }
}

final class DebuggerDetectorTests: XCTestCase {
    func testNoDebuggerIsClean() {
        XCTAssertTrue(DebuggerDetector(FakeDeviceEnvironment()).evaluate().isEmpty)
    }

    func testTracedIsDebugger() {
        let env = FakeDeviceEnvironment()
        env.traced = true
        XCTAssertEqual(DebuggerDetector(env).evaluate(), [.debugger])
    }
}

final class HookDetectorTests: XCTestCase {
    func testCleanProcessIsClean() {
        XCTAssertTrue(HookDetector(FakeDeviceEnvironment()).evaluate().isEmpty)
    }

    func testSubstrateImageIsHooking() {
        let env = FakeDeviceEnvironment()
        env.images.append("/Library/MobileSubstrate/MobileSubstrate.dylib")
        XCTAssertEqual(HookDetector(env).evaluate(), [.hooking])
    }

    func testFridaImageIsHooking() {
        let env = FakeDeviceEnvironment()
        env.images.append("/usr/lib/frida-agent.dylib")
        XCTAssertTrue(HookDetector(env).evaluate().contains(.hooking))
    }

    func testDyldInsertIsHooking() {
        let env = FakeDeviceEnvironment()
        env.environment["DYLD_INSERT_LIBRARIES"] = "/tmp/hook.dylib"
        XCTAssertTrue(HookDetector(env).evaluate().contains(.hooking))
    }

    func testFridaPortIsHooking() {
        let env = FakeDeviceEnvironment()
        env.openPorts.insert(27042)
        XCTAssertTrue(HookDetector(env).evaluate().contains(.hooking))
    }
}

final class IntegrityCheckerTests: XCTestCase {
    func testMatchingBundleIdIsClean() {
        let env = FakeDeviceEnvironment()
        env.bundleId = "com.example.app"
        let policy = IntegrityPolicy(expectedBundleId: "com.example.app")
        XCTAssertTrue(IntegrityChecker(env, policy: policy).evaluate().isEmpty)
    }

    func testMismatchedBundleIdIsRepackaged() {
        let env = FakeDeviceEnvironment()
        env.bundleId = "com.attacker.clone"
        let policy = IntegrityPolicy(expectedBundleId: "com.example.app")
        let signals = IntegrityChecker(env, policy: policy).evaluate()
        XCTAssertTrue(signals.contains(.repackaged))
        XCTAssertTrue(signals.contains(.appIntegrity))
    }

    func testEmbeddedProvisionFlaggedWhenAppStoreRequired() {
        let env = FakeDeviceEnvironment()
        env.embeddedMobileProvision = true
        let policy = IntegrityPolicy(requireAppStoreDistribution: true)
        XCTAssertTrue(IntegrityChecker(env, policy: policy).evaluate().contains(.appIntegrity))
    }

    func testMissingReceiptFlaggedWhenAppStoreRequired() {
        let env = FakeDeviceEnvironment()
        env.appStoreReceipt = false
        let policy = IntegrityPolicy(requireAppStoreDistribution: true)
        XCTAssertTrue(IntegrityChecker(env, policy: policy).evaluate().contains(.appIntegrity))
    }

    func testNoPolicyIsClean() {
        let env = FakeDeviceEnvironment()
        env.bundleId = "com.attacker.clone"
        XCTAssertTrue(IntegrityChecker(env, policy: IntegrityPolicy()).evaluate().isEmpty)
    }
}

final class NetworkRiskDetectorTests: XCTestCase {
    func testNoProxyIsClean() {
        XCTAssertTrue(NetworkRiskDetector(FakeDeviceEnvironment()).evaluate().isEmpty)
    }

    func testProxyIsProxyAndMitm() {
        let env = FakeDeviceEnvironment()
        env.proxy = "10.0.0.1"
        let signals = NetworkRiskDetector(env).evaluate()
        XCTAssertTrue(signals.contains(.proxy))
        XCTAssertTrue(signals.contains(.networkMitm))
    }
}
