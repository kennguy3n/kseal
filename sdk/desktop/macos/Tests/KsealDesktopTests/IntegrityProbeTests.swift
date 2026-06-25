import XCTest
@testable import KsealDesktop

/// Unit-tests the macOS integrity-check logic against controlled signing
/// snapshots: valid vs. tampered signature, missing notarization, wrong team
/// id, dylib injection, and disabled hardened runtime.
final class IntegrityProbeTests: XCTestCase {

    private let strictPolicy = DesktopIntegrityPolicy(
        expectedTeamIdentifier: "ABCDE12345",
        expectedSigningIdentifier: "com.example.app",
        requireValidSignature: true,
        requireNotarization: true,
        requireHardenedRuntime: true
    )

    // MARK: - Code signature

    func testValidSignatureCleanApp() {
        let env = FakeDesktopEnvironment()
        let signals = CodeSignatureProbe(env, policy: strictPolicy).evaluate()
        XCTAssertTrue(signals.isEmpty)
    }

    func testUnsignedBinaryRaisesTamperAndIntegrity() {
        let env = FakeDesktopEnvironment()
        env.signing.isSigned = false
        env.signing.signatureValid = false
        let signals = CodeSignatureProbe(env, policy: strictPolicy).evaluate()
        XCTAssertTrue(signals.contains(.tamper))
        XCTAssertTrue(signals.contains(.appIntegrity))
    }

    func testTamperedSignatureRaisesTamper() {
        let env = FakeDesktopEnvironment()
        env.signing.signatureValid = false // signed but CDHash/resources mismatch
        let signals = CodeSignatureProbe(env, policy: strictPolicy).evaluate()
        XCTAssertTrue(signals.contains(.tamper))
        XCTAssertTrue(signals.contains(.appIntegrity))
    }

    func testWrongTeamIdentifierRaisesRepackaged() {
        let env = FakeDesktopEnvironment()
        env.signing.teamIdentifier = "ZZZZZ99999"
        let signals = CodeSignatureProbe(env, policy: strictPolicy).evaluate()
        XCTAssertTrue(signals.contains(.repackaged))
        XCTAssertTrue(signals.contains(.appIntegrity))
        XCTAssertFalse(signals.contains(.tamper)) // signature itself is valid
    }

    func testWrongSigningIdentifierRaisesRepackaged() {
        let env = FakeDesktopEnvironment()
        env.signing.signingIdentifier = "com.attacker.clone"
        let signals = CodeSignatureProbe(env, policy: strictPolicy).evaluate()
        XCTAssertTrue(signals.contains(.repackaged))
    }

    func testUnconfiguredPolicyNeverFalsePositives() {
        let env = FakeDesktopEnvironment()
        env.signing.teamIdentifier = "anything"
        env.signing.signingIdentifier = "anything"
        // No expected identifiers, signature requirement off.
        let policy = DesktopIntegrityPolicy(
            requireValidSignature: false,
            requireNotarization: false,
            requireHardenedRuntime: false
        )
        XCTAssertTrue(CodeSignatureProbe(env, policy: policy).evaluate().isEmpty)
    }

    // MARK: - Notarization

    func testMissingNotarizationRaisesIntegrity() {
        let env = FakeDesktopEnvironment()
        env.signing.isNotarized = false
        let signals = NotarizationProbe(env, policy: strictPolicy).evaluate()
        XCTAssertEqual(signals, [.appIntegrity])
    }

    func testNotarizationIgnoredWhenNotRequired() {
        let env = FakeDesktopEnvironment()
        env.signing.isNotarized = false
        let policy = DesktopIntegrityPolicy(requireNotarization: false)
        XCTAssertTrue(NotarizationProbe(env, policy: policy).evaluate().isEmpty)
    }

    func testNotarizationSkippedForUnsignedBinary() {
        let env = FakeDesktopEnvironment()
        env.signing.isSigned = false
        env.signing.isNotarized = false
        // Unsigned binaries are owned by the code-signature probe; notarization
        // does not double-count.
        XCTAssertTrue(NotarizationProbe(env, policy: strictPolicy).evaluate().isEmpty)
    }

    // MARK: - Hardened runtime

    func testHardenedRuntimeDisabledRaisesEnvironment() {
        let env = FakeDesktopEnvironment()
        env.signing.hardenedRuntimeEnabled = false
        let signals = HardenedRuntimeProbe(env, policy: strictPolicy).evaluate()
        XCTAssertEqual(signals, [.environment])
    }

    func testHardenedRuntimeCleanWhenEnabled() {
        let env = FakeDesktopEnvironment()
        XCTAssertTrue(HardenedRuntimeProbe(env, policy: strictPolicy).evaluate().isEmpty)
    }

    // MARK: - Dylib injection

    func testDyldInsertLibrariesRaisesHooking() {
        let env = FakeDesktopEnvironment()
        env.environment["DYLD_INSERT_LIBRARIES"] = "/tmp/evil.dylib"
        XCTAssertEqual(DylibInjectionProbe(env).evaluate(), [.hooking])
    }

    func testForeignImageRaisesHooking() {
        let env = FakeDesktopEnvironment()
        env.foreignImages = ["/tmp/injected.dylib"]
        XCTAssertEqual(DylibInjectionProbe(env).evaluate(), [.hooking])
    }

    func testNoInjectionIsClean() {
        XCTAssertTrue(DylibInjectionProbe(FakeDesktopEnvironment()).evaluate().isEmpty)
    }

    func testEmptyInjectionEnvVarIsClean() {
        let env = FakeDesktopEnvironment()
        env.environment["DYLD_INSERT_LIBRARIES"] = ""
        XCTAssertTrue(DylibInjectionProbe(env).evaluate().isEmpty)
    }

    func testNativeHookPresentRaisesHooking() {
        let env = FakeDesktopEnvironment()
        env.nativeHook = 1
        XCTAssertEqual(DylibInjectionProbe(env).evaluate(), [.hooking])
    }

    func testNativeHookUnavailableIsClean() {
        let env = FakeDesktopEnvironment()
        env.nativeHook = -1
        XCTAssertTrue(DylibInjectionProbe(env).evaluate().isEmpty)
    }

    func testNativeHookNotConsultedWhenDisabled() {
        let env = FakeDesktopEnvironment()
        env.nativeHook = 1
        // With an allowlist configured the SDK passes consultNativeHook: false,
        // so the allowlist-unaware native scan must not raise the signal.
        XCTAssertTrue(DylibInjectionProbe(env, consultNativeHook: false).evaluate().isEmpty)
    }

    // MARK: - Debugger (opt-in)

    func testDebuggerProbeDetectsTrace() {
        let env = FakeDesktopEnvironment()
        env.traced = true
        XCTAssertEqual(DebuggerProbe(env).evaluate(), [.debugger])
    }

    func testDebuggerProbeCleanWhenUntraced() {
        XCTAssertTrue(DebuggerProbe(FakeDesktopEnvironment()).evaluate().isEmpty)
    }

    func testDebuggerProbeDetectsNativeTracer() {
        let env = FakeDesktopEnvironment()
        env.nativeDebugger = 1
        XCTAssertEqual(DebuggerProbe(env).evaluate(), [.debugger])
    }

    func testDebuggerProbeNativeUnavailableIsClean() {
        let env = FakeDesktopEnvironment()
        env.nativeDebugger = -1
        XCTAssertTrue(DebuggerProbe(env).evaluate().isEmpty)
    }

    // MARK: - Self-integrity (digest baseline)

    private let codePath = "/Applications/App.app/Contents/MacOS/App"
    private let artifactPath = "/Applications/App.app/Contents/Info.plist"
    private let baseline = String(repeating: "ab", count: 32)

    func testSelfIntegrityEmptyPolicyIsSilent() {
        let env = FakeDesktopEnvironment()
        XCTAssertTrue(SelfIntegrityProbe(env, policy: DesktopTamperPolicy()).evaluate().isEmpty)
    }

    func testSelfIntegrityMatchingCodeDigestIsClean() {
        let env = FakeDesktopEnvironment()
        env.fileDigests[codePath] = baseline
        let policy = DesktopTamperPolicy(expectedCodeSha256: [codePath: baseline])
        XCTAssertTrue(SelfIntegrityProbe(env, policy: policy).evaluate().isEmpty)
    }

    func testSelfIntegrityCaseInsensitiveCodeDigestIsClean() {
        let env = FakeDesktopEnvironment()
        env.fileDigests[codePath] = baseline.uppercased()
        let policy = DesktopTamperPolicy(expectedCodeSha256: [codePath: baseline])
        XCTAssertTrue(SelfIntegrityProbe(env, policy: policy).evaluate().isEmpty)
    }

    func testSelfIntegrityMismatchedCodeDigestRaisesTamper() {
        let env = FakeDesktopEnvironment()
        env.fileDigests[codePath] = String(repeating: "cd", count: 32)
        let policy = DesktopTamperPolicy(expectedCodeSha256: [codePath: baseline])
        XCTAssertEqual(SelfIntegrityProbe(env, policy: policy).evaluate(), [.tamper])
    }

    func testSelfIntegrityMismatchedArtifactDigestRaisesAppIntegrity() {
        let env = FakeDesktopEnvironment()
        env.fileDigests[artifactPath] = String(repeating: "cd", count: 32)
        let policy = DesktopTamperPolicy(expectedArtifactSha256: [artifactPath: baseline])
        XCTAssertEqual(SelfIntegrityProbe(env, policy: policy).evaluate(), [.appIntegrity])
    }

    func testSelfIntegrityBothMismatchesRaiseBothSignals() {
        let env = FakeDesktopEnvironment()
        env.fileDigests[codePath] = String(repeating: "cd", count: 32)
        env.fileDigests[artifactPath] = String(repeating: "cd", count: 32)
        let policy = DesktopTamperPolicy(
            expectedCodeSha256: [codePath: baseline],
            expectedArtifactSha256: [artifactPath: baseline]
        )
        XCTAssertEqual(SelfIntegrityProbe(env, policy: policy).evaluate(), [.tamper, .appIntegrity])
    }

    func testSelfIntegrityUnmeasurableFileIsSilent() {
        // A file whose digest cannot be computed (nil) must never raise a signal.
        let env = FakeDesktopEnvironment()
        let policy = DesktopTamperPolicy(expectedCodeSha256: [codePath: baseline])
        XCTAssertTrue(SelfIntegrityProbe(env, policy: policy).evaluate().isEmpty)
    }

    func testSelfIntegrityFailClosedRaisesTamperForUnmeasurableCode() {
        // Opt-in fail-closed: an unmeasurable baseline-registered code file is
        // treated as a mismatch instead of being skipped.
        let env = FakeDesktopEnvironment()
        let policy = DesktopTamperPolicy(expectedCodeSha256: [codePath: baseline], failClosedOnUnmeasurable: true)
        XCTAssertEqual(SelfIntegrityProbe(env, policy: policy).evaluate(), [.tamper])
    }

    func testSelfIntegrityFailClosedRaisesAppIntegrityForUnmeasurableArtifact() {
        let env = FakeDesktopEnvironment()
        let policy = DesktopTamperPolicy(expectedArtifactSha256: [artifactPath: baseline], failClosedOnUnmeasurable: true)
        XCTAssertEqual(SelfIntegrityProbe(env, policy: policy).evaluate(), [.appIntegrity])
    }

    func testSelfIntegrityFailClosedStillCleanWhenMeasurableAndMatching() {
        // The flag must not turn a measurable, matching file into a signal.
        let env = FakeDesktopEnvironment()
        env.fileDigests[codePath] = baseline
        let policy = DesktopTamperPolicy(expectedCodeSha256: [codePath: baseline], failClosedOnUnmeasurable: true)
        XCTAssertTrue(SelfIntegrityProbe(env, policy: policy).evaluate().isEmpty)
    }
}
