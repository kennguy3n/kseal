import XCTest
@testable import KsealDesktop

final class EnterprisePolicyTests: XCTestCase {

    func testStrictBaselineRelaxesNothing() {
        let p = EnterprisePolicy.strict
        XCTAssertTrue(p.isStrict)
        XCTAssertFalse(p.permitDebugger)
        XCTAssertTrue(p.injectionAllowlist.isEmpty)
        XCTAssertEqual(p.telemetryVerbosity, .standard)
        XCTAssertFalse(p.requireHardwareBackedProofKey)
        XCTAssertFalse(p.allowsModule("/anything"))
    }

    func testPartialJsonKeepsStrictDefaultsForMissingKeys() throws {
        let json = Data(#"{ "permitDebugger": true }"#.utf8)
        let p = try JSONDecoder().decode(EnterprisePolicy.self, from: json)
        XCTAssertTrue(p.permitDebugger)
        // Unspecified controls stay strict.
        XCTAssertTrue(p.injectionAllowlist.isEmpty)
        XCTAssertEqual(p.telemetryVerbosity, .standard)
        XCTAssertFalse(p.requireHardwareBackedProofKey)
        XCTAssertFalse(p.isStrict)
    }

    func testFullJsonRoundTrip() throws {
        let json = Data(#"""
        {
          "permitDebugger": true,
          "injectionAllowlist": ["/Library/Acme/plugin.dylib", "/opt/agents/"],
          "telemetryVerbosity": "minimal",
          "requireHardwareBackedProofKey": true
        }
        """#.utf8)
        let p = try JSONDecoder().decode(EnterprisePolicy.self, from: json)
        XCTAssertTrue(p.permitDebugger)
        XCTAssertEqual(p.telemetryVerbosity, .minimal)
        XCTAssertTrue(p.requireHardwareBackedProofKey)
        XCTAssertEqual(p.injectionAllowlist.count, 2)
    }

    func testAllowsModuleExactAndPrefix() {
        let p = EnterprisePolicy(injectionAllowlist: ["/Library/Acme/plugin.dylib", "/opt/agents/"])
        XCTAssertTrue(p.allowsModule("/Library/Acme/plugin.dylib"))      // exact
        XCTAssertTrue(p.allowsModule("/opt/agents/telemetry.dylib"))     // prefix
        XCTAssertFalse(p.allowsModule("/opt/agents"))                    // prefix needs trailing /
        XCTAssertFalse(p.allowsModule("/tmp/evil.dylib"))                // not listed
        XCTAssertFalse(p.allowsModule("/Library/Acme/plugin.dylib.bak")) // exact only
    }

    func testFileProviderReadsPolicy() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("kseal-policy-\(UUID().uuidString).json")
        try Data(#"{ "telemetryVerbosity": "verbose" }"#.utf8).write(to: url)
        let provider = FileEnterprisePolicyProvider(url: url)
        XCTAssertEqual(provider.currentPolicy().telemetryVerbosity, .verbose)
    }

    func testFileProviderFailsSafeOnMissingFile() {
        let url = URL(fileURLWithPath: "/nonexistent/\(UUID().uuidString).json")
        XCTAssertTrue(FileEnterprisePolicyProvider(url: url).currentPolicy().isStrict)
    }

    func testFileProviderFailsSafeOnMalformedJson() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("kseal-bad-\(UUID().uuidString).json")
        try Data("not json".utf8).write(to: url)
        XCTAssertTrue(FileEnterprisePolicyProvider(url: url).currentPolicy().isStrict)
    }

    func testStaticProvider() {
        let p = EnterprisePolicy(permitDebugger: true)
        XCTAssertEqual(StaticEnterprisePolicyProvider(p).currentPolicy(), p)
        XCTAssertTrue(StaticEnterprisePolicyProvider().currentPolicy().isStrict)
    }
}
