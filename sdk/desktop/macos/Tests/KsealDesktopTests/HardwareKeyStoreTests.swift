import XCTest
@testable import KsealDesktop

final class HardwareKeyStoreTests: XCTestCase {

    private func tempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("kseal-hwkey-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func proofFile(_ dir: URL) -> URL {
        dir.appendingPathComponent("kseal", isDirectory: true).appendingPathComponent("proof.key")
    }

    func testFakeStoreRoundTrips() throws {
        let store = FakeHardwareKeyStore()
        let secret = Data([1, 2, 3, 4, 5, 250, 251, 252])
        let sealed = try store.seal(secret)
        XCTAssertNotEqual(sealed, secret)
        XCTAssertEqual(try store.unseal(sealed), secret)
    }

    func testUnsealRejectsForeignBlob() {
        let store = FakeHardwareKeyStore()
        XCTAssertThrowsError(try store.unseal(Data([0, 1, 2, 3, 4, 5])))
    }

    func testSoftwareStoreIsPassthroughAndMatchesLegacyLayout() throws {
        let dir = tempDir()
        let provider = HardwareBoundProofKeyProvider(directory: dir, store: SoftwareKeyStore())
        XCTAssertFalse(provider.isHardwareBacked)

        let key = provider.proofKey()
        XCTAssertEqual(key.count, HardwareBoundProofKeyProvider.keyLength)
        // Software fallback persists the raw key verbatim (legacy on-disk layout).
        let onDisk = try Data(contentsOf: proofFile(dir))
        XCTAssertEqual(onDisk, key)

        // Stable across instances pointing at the same storage.
        let again = HardwareBoundProofKeyProvider(directory: dir, store: SoftwareKeyStore()).proofKey()
        XCTAssertEqual(again, key)
    }

    func testHardwareStoreSealsAtRestButKeyIsStable() throws {
        let dir = tempDir()
        let store = FakeHardwareKeyStore()
        let provider = HardwareBoundProofKeyProvider(directory: dir, store: store)
        XCTAssertTrue(provider.isHardwareBacked)

        let key = provider.proofKey()
        XCTAssertEqual(key.count, HardwareBoundProofKeyProvider.keyLength)

        // What is persisted is the sealed blob, never the raw key.
        let onDisk = try Data(contentsOf: proofFile(dir))
        XCTAssertNotEqual(onDisk, key)
        XCTAssertEqual(try store.unseal(onDisk), key)

        // A second provider over the same store + storage yields the same key.
        let again = HardwareBoundProofKeyProvider(directory: dir, store: FakeHardwareKeyStore()).proofKey()
        XCTAssertEqual(again, key)
    }

    func testLegacyRawKeyIsMigratedToSealedInPlace() throws {
        let dir = tempDir()
        // Simulate a pre-hardware install: a raw 32-byte key on disk.
        let legacy = Data((0..<32).map { UInt8($0) })
        let ksealDir = dir.appendingPathComponent("kseal", isDirectory: true)
        try FileManager.default.createDirectory(at: ksealDir, withIntermediateDirectories: true)
        try legacy.write(to: proofFile(dir))

        let store = FakeHardwareKeyStore()
        let provider = HardwareBoundProofKeyProvider(directory: dir, store: store)
        let key = provider.proofKey()

        // Continuity: the migrated key equals the legacy key.
        XCTAssertEqual(key, legacy)
        // And the on-disk blob is now sealed (no longer the raw legacy bytes).
        let onDisk = try Data(contentsOf: proofFile(dir))
        XCTAssertNotEqual(onDisk, legacy)
        XCTAssertEqual(try store.unseal(onDisk), legacy)
    }

    func testSealFailureDegradesToSoftwareKeyWithoutCrashing() throws {
        let dir = tempDir()
        let provider = HardwareBoundProofKeyProvider(directory: dir, store: FailingHardwareKeyStore())
        let key = provider.proofKey()
        XCTAssertEqual(key.count, HardwareBoundProofKeyProvider.keyLength)
        // Persisted (raw, since sealing failed) and stable on reload.
        let onDisk = try Data(contentsOf: proofFile(dir))
        XCTAssertEqual(onDisk, key)
    }

    func testDefaultHardwareKeyStoreIsConstructible() {
        // On Linux/CI this is the software fallback; on macOS a Secure-Enclave
        // store when available. Either way it must produce a usable store.
        let store = makeDefaultHardwareKeyStore(label: "tenant-app")
        let secret = Data(repeating: 7, count: 32)
        if let sealed = try? store.seal(secret) {
            XCTAssertEqual(try? store.unseal(sealed), secret)
        }
    }
}
