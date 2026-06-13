import XCTest
@testable import KsealHardenCore

/// Records the last request and returns a scripted response or throws.
final class MockTransport: HTTPTransport {
    var lastRequest: HTTPRequestSpec?
    var response: HTTPResponseSpec
    var error: Error?

    init(response: HTTPResponseSpec = HTTPResponseSpec(statusCode: 200, body: Data())) {
        self.response = response
    }

    func send(_ request: HTTPRequestSpec) throws -> HTTPResponseSpec {
        lastRequest = request
        if let error = error { throw error }
        return response
    }
}

final class RegistryClientTests: XCTestCase {
    private func manifest() -> BuildProofManifest {
        BuildProofManifest(
            sdkVersion: "0.1.0",
            buildHash: "hash-abc",
            versionName: "1.0.0",
            versionCode: 7,
            polymorphism: .init(seedDigest: "seed-digest"),
            toolVersions: ["swift": "5.10.1"],
            transforms: [.init(kind: "string-obfuscation", algorithm: "seed-xor/sha256-ctr", count: 1)],
            modules: ["string-hardening"],
            provenance: .init(generatedAt: "2026-06-13T03:00:00Z", generator: "kseal-harden/0.1.0", host: "test")
        )
    }

    private func config() -> RegistryConfig {
        RegistryConfig(
            baseURL: URL(string: "https://registry.kseal.test")!,
            apiKey: "ksk_abc_secret",
            tenantId: "tenant-1",
            appId: "app-1",
            protectionProfileId: "profile-1"
        )
    }

    func testRequestWireFormat() throws {
        let client = RegistryClient(config: config(), transport: MockTransport())
        let req = try client.makeCreateBuildRequest(manifest: manifest())

        XCTAssertEqual(req.method, "POST")
        XCTAssertEqual(req.url.absoluteString, "https://registry.kseal.test/kseal.v1.RegistryService/CreateBuild")
        XCTAssertEqual(req.headers["Authorization"], "Bearer ksk_abc_secret")
        XCTAssertEqual(req.headers["Content-Type"], "application/json")
        XCTAssertEqual(req.headers["Connect-Protocol-Version"], "1")

        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: req.body) as? [String: Any])
        XCTAssertEqual(body["tenantId"] as? String, "tenant-1")
        XCTAssertEqual(body["appId"] as? String, "app-1")
        XCTAssertEqual(body["buildHash"] as? String, "hash-abc")
        XCTAssertEqual(body["versionName"] as? String, "1.0.0")
        // int64 encoded as string per proto3 JSON.
        XCTAssertEqual(body["versionCode"] as? String, "7")
        XCTAssertEqual(body["protectionProfileId"] as? String, "profile-1")
        // manifest is a JSON *string* field.
        let manifestStr = try XCTUnwrap(body["manifest"] as? String)
        let nested = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(manifestStr.utf8)) as? [String: Any])
        XCTAssertEqual(nested["buildHash"] as? String, "hash-abc")
    }

    func testCreateBuildParsesId() throws {
        let respBody = try JSONSerialization.data(withJSONObject: ["build": ["id": "build-xyz"]])
        let transport = MockTransport(response: HTTPResponseSpec(statusCode: 200, body: respBody))
        let client = RegistryClient(config: config(), transport: transport)
        XCTAssertEqual(try client.createBuild(manifest: manifest()), "build-xyz")
        XCTAssertNotNil(transport.lastRequest)
    }

    func testCreateBuildThrowsOnHTTPError() {
        let transport = MockTransport(response: HTTPResponseSpec(statusCode: 401, body: Data("invalid api key".utf8)))
        let client = RegistryClient(config: config(), transport: transport)
        XCTAssertThrowsError(try client.createBuild(manifest: manifest()))
    }

    func testRegistrarRegistersOnSuccess() throws {
        let respBody = try JSONSerialization.data(withJSONObject: ["build": ["id": "build-1"]])
        let transport = MockTransport(response: HTTPResponseSpec(statusCode: 200, body: respBody))
        let registrar = BuildProofRegistrar(transport: transport)
        let artifact = tempURL()
        let result = registrar.register(manifest: manifest(), config: config(), offlineArtifact: artifact)
        XCTAssertEqual(try result.get(), .registered(buildId: "build-1"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: artifact.path), "no offline artifact when registered")
    }

    func testRegistrarFallsBackOfflineOnTransportError() throws {
        let transport = MockTransport()
        transport.error = RegistryError.transport("connection refused")
        let registrar = BuildProofRegistrar(transport: transport)
        let artifact = tempURL()
        let result = registrar.register(manifest: manifest(), config: config(), offlineArtifact: artifact)
        XCTAssertEqual(try result.get(), .offline(artifactPath: artifact.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: artifact.path))
        let written = try BuildProofManifest.decode(from: Data(contentsOf: artifact))
        XCTAssertEqual(written.buildHash, "hash-abc")
    }

    func testRegistrarOfflineWhenUnconfigured() throws {
        let registrar = BuildProofRegistrar(transport: MockTransport())
        let artifact = tempURL()
        let result = registrar.register(manifest: manifest(), config: nil, offlineArtifact: artifact)
        XCTAssertEqual(try result.get(), .offline(artifactPath: artifact.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: artifact.path))
    }

    func testConfigFromEnvironment() {
        let env = [
            "KSEAL_REGISTRY_URL": "https://r.test",
            "KSEAL_API_KEY": "ksk_a_b",
            "KSEAL_TENANT_ID": "t1",
            "KSEAL_APP_ID": "a1",
        ]
        let config = RegistryConfig.fromEnvironment(env)
        XCTAssertEqual(config?.tenantId, "t1")
        XCTAssertNil(RegistryConfig.fromEnvironment(["KSEAL_REGISTRY_URL": "https://r.test"]))
    }

    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("kseal-test-\(UUID().uuidString)")
            .appendingPathComponent("build-proof.json")
    }
}
