import XCTest
@testable import KsealDesktop

private struct FixedClock: Clock {
    let millis: Int64
    func nowMillis() -> Int64 { millis }
}

/// Verifies the effect of enterprise controls on the live SDK against the real
/// Rust core with a controlled environment.
final class EnterprisePolicyWiringTests: XCTestCase {

    private func makeSDK(
        env: DesktopEnvironment,
        enterprise: EnterprisePolicy,
        sink: BufferingTelemetrySink = BufferingTelemetrySink(),
        enabledProbes: Set<String>? = nil,
        proofKeyIsHardwareBacked: Bool = false
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
            options: KsealDesktopOptions(integrityPolicy: policy, enabledProbes: enabledProbes),
            configProvider: FileConfigProvider(directory: FileManager.default.temporaryDirectory),
            telemetrySink: sink,
            attestor: LocalCodeIntegrityAttestor(),
            installIdentityHash: "deadbeef",
            clock: FixedClock(millis: 1_700_000_000_000),
            proofKeyIsHardwareBacked: proofKeyIsHardwareBacked,
            enterprisePolicy: enterprise
        )
    }

    func testStrictPolicyMatchesPreExistingBehavior() throws {
        let env = FakeDesktopEnvironment()
        env.foreignImages = ["/tmp/inject.dylib"]
        let assessment = try makeSDK(env: env, enterprise: .strict).evaluateRisk()
        XCTAssertTrue(assessment.signals.contains(.hooking))
    }

    func testInjectionAllowlistSuppressesSanctionedModule() throws {
        let env = FakeDesktopEnvironment()
        env.foreignImages = ["/Library/Acme/plugin.dylib"]
        let policy = EnterprisePolicy(injectionAllowlist: ["/Library/Acme/"])
        let assessment = try makeSDK(env: env, enterprise: policy).evaluateRisk()
        XCTAssertFalse(assessment.signals.contains(.hooking))
    }

    func testAllowlistStillFlagsNonListedModule() throws {
        let env = FakeDesktopEnvironment()
        env.foreignImages = ["/Library/Acme/plugin.dylib", "/tmp/evil.dylib"]
        let policy = EnterprisePolicy(injectionAllowlist: ["/Library/Acme/"])
        let assessment = try makeSDK(env: env, enterprise: policy).evaluateRisk()
        XCTAssertTrue(assessment.signals.contains(.hooking))
    }

    func testStrictPolicyConsultsNativeHook() throws {
        let env = FakeDesktopEnvironment()
        env.nativeHook = 1 // no allowlist configured → native scan is consulted
        let assessment = try makeSDK(env: env, enterprise: .strict).evaluateRisk()
        XCTAssertTrue(assessment.signals.contains(.hooking))
    }

    func testInjectionAllowlistSuppressesNativeHook() throws {
        let env = FakeDesktopEnvironment()
        env.nativeHook = 1 // allowlist-unaware native scan would fire ...
        let policy = EnterprisePolicy(injectionAllowlist: ["/Library/Acme/"])
        let assessment = try makeSDK(env: env, enterprise: policy).evaluateRisk()
        // ... but a configured allowlist defers to the allowlist-aware managed
        // checks, so the native scan is not consulted.
        XCTAssertFalse(assessment.signals.contains(.hooking))
    }

    func testPermitDebuggerDropsDebuggerProbeEvenWhenEnabled() throws {
        let env = FakeDesktopEnvironment()
        env.traced = true
        let enabled: Set<String> = ["macos.debugger"]
        // Without permit: the explicitly enabled debugger probe fires.
        let strict = try makeSDK(env: env, enterprise: .strict, enabledProbes: enabled).evaluateRisk()
        XCTAssertTrue(strict.signals.contains(.debugger))
        // With permit: it is suppressed for the managed developer machine.
        let permitted = try makeSDK(
            env: env, enterprise: EnterprisePolicy(permitDebugger: true), enabledProbes: enabled
        ).evaluateRisk()
        XCTAssertFalse(permitted.signals.contains(.debugger))
    }

    func testRequireHardwareBackedProofKeyRaisesSecureHwMissing() throws {
        let env = FakeDesktopEnvironment()
        let policy = EnterprisePolicy(requireHardwareBackedProofKey: true)
        // Hardware unavailable → signal raised.
        let missing = try makeSDK(env: env, enterprise: policy, proofKeyIsHardwareBacked: false).evaluateRisk()
        XCTAssertTrue(missing.signals.contains(.secureHwMissing))
        // Hardware present → not raised.
        let present = try makeSDK(env: env, enterprise: policy, proofKeyIsHardwareBacked: true).evaluateRisk()
        XCTAssertFalse(present.signals.contains(.secureHwMissing))
        // Control off → never raised even without hardware.
        let off = try makeSDK(env: env, enterprise: .strict, proofKeyIsHardwareBacked: false).evaluateRisk()
        XCTAssertFalse(off.signals.contains(.secureHwMissing))
    }

    func testMinimalVerbosityDropsCleanEvents() throws {
        let env = FakeDesktopEnvironment() // clean, signed
        let sink = BufferingTelemetrySink()
        let sdk = try makeSDK(
            env: env, enterprise: EnterprisePolicy(telemetryVerbosity: .minimal), sink: sink
        )
        sdk.reportEvent(.policyDecision)
        sdk.flushTelemetry()
        XCTAssertTrue(sink.drain().isEmpty, "clean event should be dropped at minimal verbosity")
    }

    func testStandardVerbosityKeepsCleanEvents() throws {
        let env = FakeDesktopEnvironment()
        let sink = BufferingTelemetrySink()
        let sdk = try makeSDK(env: env, enterprise: .strict, sink: sink)
        sdk.reportEvent(.policyDecision)
        sdk.flushTelemetry()
        XCTAssertFalse(sink.drain().isEmpty, "clean event should be recorded at standard verbosity")
    }
}
