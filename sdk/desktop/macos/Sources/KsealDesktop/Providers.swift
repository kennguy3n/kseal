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

/// Derives a filesystem-safe, collision-resistant directory component that
/// isolates one tenant+app's private storage (config, proof key, install id)
/// from every other tenant/app sharing the same user account.
enum StorageScope {
    static func component(tenantId: String, appId: String) -> String {
        let message = Data("\(tenantId)\u{0}\(appId)".utf8)
        #if canImport(CryptoKit)
        return SHA256.hash(data: message).prefix(16).map { String(format: "%02x", $0) }.joined()
        #else
        func fnv(_ seed: UInt64, _ bytes: Data) -> UInt64 {
            var hash = seed
            for byte in bytes {
                hash ^= UInt64(byte)
                hash = hash &* 0x100000001b3
            }
            return hash
        }
        let a = fnv(0xcbf29ce484222325, message)
        let b = fnv(a ^ 0x5c5c5c5c5c5c5c5c, message)
        return String(format: "%016llx%016llx", a, b)
        #endif
    }
}

/// Source of the tenant's signed config bytes.
///
/// `cachedConfig()` is read at launch (no network); `fetchConfig()` is invoked
/// only by `KsealDesktop.refreshConfig()` (on demand) and is where the host
/// wires the signed-config CDN. The default never performs network I/O —
/// keeping launch network-free per the performance budget.
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

/// Proof-key provider that seals the request-proof HMAC key with a
/// `HardwareKeyStore` before persisting it.
///
/// With a hardware-backed store (macOS Secure Enclave) the at-rest key is bound
/// to the device's secure element and cannot be lifted from disk and replayed
/// elsewhere. With the software fallback the persisted bytes are byte-identical
/// to `DefaultProofKeyProvider`, so existing installs keep their key — and thus
/// their server-side trust continuity. The request-proof byte layout is
/// unchanged either way: the core still computes `HMAC(proofKey, …)`; only how
/// `proofKey` is protected at rest changes.
struct HardwareBoundProofKeyProvider: ProofKeyProvider {
    private let fileURL: URL
    private let store: HardwareKeyStore

    static let keyLength = 32

    init(directory: URL, store: HardwareKeyStore) {
        let dir = directory.appendingPathComponent("kseal", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.fileURL = dir.appendingPathComponent("proof.key")
        self.store = store
    }

    /// Whether the persisted key is sealed by a hardware-backed element.
    var isHardwareBacked: Bool { store.isHardwareBacked }

    func proofKey() -> Data {
        if let stored = try? Data(contentsOf: fileURL), !stored.isEmpty {
            if let key = try? store.unseal(stored), key.count == Self.keyLength {
                return key
            }
            // A blob we cannot unseal but that is exactly a legacy raw key:
            // adopt it (preserving trust continuity) and re-seal it in place.
            if stored.count == Self.keyLength {
                if let resealed = try? store.seal(stored) {
                    try? resealed.write(to: fileURL, options: .atomic)
                }
                return stored
            }
            // Otherwise the blob is unusable — regenerate below.
        }

        var bytes = [UInt8](repeating: 0, count: Self.keyLength)
        SecureRandom.fill(&bytes)
        let key = Data(bytes)
        guard let sealed = try? store.seal(key) else {
            // Hardware seal failed unexpectedly: persist the raw key so the SDK
            // stays functional (software-equivalent) rather than bricking the host.
            return DefaultProofKeyProvider.createOrReadExisting(at: fileURL, candidate: key)
        }
        let persisted = DefaultProofKeyProvider.createOrReadExisting(at: fileURL, candidate: sealed)
        // Re-unseal the race winner's blob so concurrent creators converge.
        return (try? store.unseal(persisted)) ?? key
    }
}

/// Persistent random proof key stored in the app's private storage.
///
/// This is the **software fallback** used when no hardware element is available;
/// `HardwareBoundProofKeyProvider` wraps it on macOS Secure Enclave. It also owns
/// the race-tolerant first-launch create helper the hardware provider reuses.
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
        var bytes = [UInt8](repeating: 0, count: 32)
        SecureRandom.fill(&bytes)
        let key = Data(bytes)
        return Self.createOrReadExisting(at: fileURL, candidate: key)
    }

    /// Materializes a first-launch secret with an exclusive create, tolerating a
    /// concurrent creator. `.withoutOverwriting` makes the create-vs-create race a
    /// loser-reads situation: whoever wins keeps its bytes; everyone else re-reads
    /// the winner's file, so all callers converge on one value (no last-writer-wins
    /// churn).
    static func createOrReadExisting(at url: URL, candidate: Data) -> Data {
        do {
            try candidate.write(to: url, options: [.withoutOverwriting])
            return candidate
        } catch {
            if let existing = try? Data(contentsOf: url), !existing.isEmpty {
                return existing
            }
            return candidate
        }
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
        var bytes = [UInt8](repeating: 0, count: 16)
        SecureRandom.fill(&bytes)
        let id = Data(bytes)
        return DefaultProofKeyProvider.createOrReadExisting(at: fileURL, candidate: id)
    }

    /// Lowercase-hex tenant-scoped HMAC of the install id (never the raw id).
    ///
    /// Mirrors the mobile SDKs exactly —
    /// `HMAC-SHA256(key=installId, message="tenant\0app")` — so every platform
    /// shares one keyed construction (HMAC also avoids the length-extension
    /// weakness of a plain `SHA256(id || ctx)` concatenation).
    func tenantScopedHash(tenantId: String, appId: String) -> String {
        let message = Data("\(tenantId)\u{0}\(appId)".utf8)
        return Self.hmacSha256Hex(key: installId(), message: message)
    }

    static func hmacSha256Hex(key: Data, message: Data) -> String {
        #if canImport(CryptoKit)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return mac.map { String(format: "%02x", $0) }.joined()
        #else
        // Non-Apple host (test/CI) fallback: a deterministic, non-cryptographic
        // keyed digest. Production runs on macOS and uses HMAC-SHA256.
        func fnv(_ seed: UInt64, _ bytes: Data) -> UInt64 {
            var hash = seed
            for byte in bytes {
                hash ^= UInt64(byte)
                hash = hash &* 0x100000001b3
            }
            return hash
        }
        let keyed = fnv(0xcbf29ce484222325, key) ^ 0x5c5c5c5c5c5c5c5c
        return String(format: "%016llx", fnv(keyed, message))
        #endif
    }
}

/// Cryptographically secure random bytes from the OS CSPRNG.
///
/// Uses the platform-appropriate public API: `SecRandomCopyBytes` on Apple
/// platforms, `/dev/urandom` on a non-Apple test host. Proof and install keys
/// must never come from a non-cryptographic PRNG.
enum SecureRandom {
    static func fill(_ buffer: inout [UInt8]) {
        guard !buffer.isEmpty else { return }
        #if canImport(Security)
        if SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer) == errSecSuccess {
            return
        }
        #endif
        #if canImport(Glibc) || canImport(Darwin)
        if let fh = FileHandle(forReadingAtPath: "/dev/urandom"),
           let data = try? fh.read(upToCount: buffer.count), data.count == buffer.count {
            data.copyBytes(to: &buffer, count: buffer.count)
            try? fh.close()
            return
        }
        #endif
        // Last-resort fallback keeps the SDK functional in a degraded sandbox;
        // production always satisfies one of the CSPRNG paths above.
        for i in buffer.indices { buffer[i] = UInt8.random(in: .min ... .max) }
    }
}

#if canImport(Security)
import Security
#endif
