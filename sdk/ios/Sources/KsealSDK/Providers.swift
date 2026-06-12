import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Monotonic clock seam (injectable for deterministic tests).
public protocol Clock {
    func nowMillis() -> Int64
}

/// Wall-clock implementation.
public struct SystemClock: Clock {
    public init() {}
    public func nowMillis() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
}

/// Source of the tenant's signed config bytes.
///
/// `cachedConfig()` is read at launch (no network); `fetchConfig()` is invoked
/// only by `KsealSDK.refreshConfig()` (on demand) and is where the host wires
/// the signed-config CDN. The default never performs network I/O — keeping
/// launch network-free per the performance budget.
public protocol ConfigProvider {
    func cachedConfig() -> Data?
    func fetchConfig() -> Data?
    func persist(_ config: Data)
}

/// Default file-backed config cache under the app's private storage.
struct FileConfigProvider: ConfigProvider {
    private let fileURL: URL

    init(directory: URL) {
        let dir = directory.appendingPathComponent("kseal", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.fileURL = dir.appendingPathComponent("config.bin")
    }

    func cachedConfig() -> Data? { try? Data(contentsOf: fileURL) }
    func fetchConfig() -> Data? { nil }
    func persist(_ config: Data) { try? config.write(to: fileURL, options: .atomic) }
}

/// Sink for compressed telemetry batches. Telemetry never leaves the device at
/// launch; the host wires a real uploader. The default buffers batches in
/// memory so nothing is sent until the host opts in (and tests can assert).
public protocol TelemetrySink: AnyObject {
    func send(_ wirePayload: Data)
}

/// In-memory sink: retains emitted batches; performs no network I/O.
public final class BufferingTelemetrySink: TelemetrySink {
    private let lock = NSLock()
    private var batches: [Data] = []

    public init() {}

    public func send(_ wirePayload: Data) {
        lock.lock(); defer { lock.unlock() }
        batches.append(wirePayload)
    }

    public func drain() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = batches
        batches.removeAll()
        return out
    }
}

/// Supplies the instance HMAC proof key binding request proofs to this install.
public protocol ProofKeyProvider {
    func proofKey() -> Data
}

/// Persistent random proof key stored in the app's private storage.
///
/// Production should bind this to the Keychain / Secure Enclave
/// (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, non-exportable) and have the
/// core accept a Keychain-computed signature; the file-backed key here is the
/// portable default and the seam where that binding plugs in.
struct DefaultProofKeyProvider: ProofKeyProvider {
    private let fileURL: URL

    init(directory: URL) {
        let dir = directory.appendingPathComponent("kseal", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.fileURL = dir.appendingPathComponent("proof.key")
    }

    func proofKey() -> Data {
        if let existing = try? Data(contentsOf: fileURL), !existing.isEmpty {
            return existing
        }
        let key = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        try? key.write(to: fileURL, options: [.atomic])
        return key
    }
}

/// Stable, non-PII install identity. Persists a random install id and derives a
/// tenant-scoped hash of it so the server can correlate an instance without ever
/// seeing the raw id (privacy guard: tenant-scoped hashes only).
struct InstallIdentity {
    private let fileURL: URL

    init(directory: URL) {
        let dir = directory.appendingPathComponent("kseal", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.fileURL = dir.appendingPathComponent("install.id")
    }

    private func installId() -> Data {
        if let existing = try? Data(contentsOf: fileURL), !existing.isEmpty {
            return existing
        }
        let id = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
        try? id.write(to: fileURL, options: [.atomic])
        return id
    }

    /// Lowercase-hex tenant-scoped hash of the install id (never the raw id).
    func tenantScopedHash(tenantId: String, appId: String) -> String {
        var input = installId()
        input.append(Data("\(tenantId)\u{0}\(appId)".utf8))
        return Self.sha256Hex(input)
    }

    static func sha256Hex(_ data: Data) -> String {
        #if canImport(CryptoKit)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        // Non-Apple host (test/CI) fallback: a deterministic, non-cryptographic
        // digest. Production runs on Apple platforms and uses SHA-256 above.
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in data {
            hash ^= UInt64(byte)
            hash = hash &* 0x100000001b3
        }
        return String(format: "%016llx", hash)
        #endif
    }
}
