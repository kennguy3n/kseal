import XCTest
@testable import KsealDesktop

final class ProvidersTests: XCTestCase {

    private func makeDir() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("kseal-test-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testStorageScopeIsStableAndTenantAppSpecific() {
        let a = StorageScope.component(tenantId: "tenant-1", appId: "app-1")
        XCTAssertEqual(a, StorageScope.component(tenantId: "tenant-1", appId: "app-1"))
        XCTAssertNotEqual(a, StorageScope.component(tenantId: "tenant-2", appId: "app-1"))
        XCTAssertNotEqual(a, StorageScope.component(tenantId: "tenant-1", appId: "app-2"))
        XCTAssertNotNil(a.range(of: "^[0-9a-f]+$", options: .regularExpression))
    }

    func testProofKeyIsStableAcrossInstances() {
        let dir = makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let key1 = DefaultProofKeyProvider(directory: dir).proofKey()
        let key2 = DefaultProofKeyProvider(directory: dir).proofKey()
        XCTAssertEqual(key1.count, 32)
        XCTAssertEqual(key1, key2)
    }

    func testCreateOrReadExistingKeepsTheFirstWriter() {
        let dir = makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("proof.key")
        let first = DefaultProofKeyProvider.createOrReadExisting(at: url, candidate: Data([1, 1, 1]))
        let second = DefaultProofKeyProvider.createOrReadExisting(at: url, candidate: Data([2, 2, 2]))
        XCTAssertEqual(first, Data([1, 1, 1]))
        XCTAssertEqual(second, first) // loser adopts the winner's bytes
    }

    func testInstallIdentityHashIsStable() {
        let dir = makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let h1 = InstallIdentity(directory: dir).tenantScopedHash(tenantId: "t", appId: "a")
        let h2 = InstallIdentity(directory: dir).tenantScopedHash(tenantId: "t", appId: "a")
        XCTAssertEqual(h1, h2)
        XCTAssertFalse(h1.isEmpty)
    }
}
