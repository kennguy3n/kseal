import Foundation

/// A per-build polymorphism seed.
///
/// Every protected build draws a fresh, high-entropy seed. The seed drives all
/// randomized transforms (string keystreams today; symbol layout / check
/// placement as the toolkit grows) so a bypass crafted against one build does
/// not transfer to the next — the kseal "decaying bypass" model
/// (see ARCHITECTURE.md#android and ../../docs/build-hardening-ios.md).
///
/// Only the seed's **digest** ever leaves the build host (it is recorded in the
/// build-proof manifest). The raw seed is never logged, printed, or committed;
/// it stays in the build directory and is consumed by the generated decoder.
public struct PolymorphismSeed: Equatable {
    /// Raw seed material. At least 16 bytes; 32 by default.
    public let bytes: [UInt8]

    public init(bytes: [UInt8]) {
        precondition(bytes.count >= 16, "polymorphism seed must be at least 16 bytes")
        self.bytes = bytes
    }

    /// Draws a cryptographically random seed.
    ///
    /// Uses the platform CSPRNG via `SystemRandomNumberGenerator`, which is
    /// backed by `arc4random`/`getrandom` — public, documented, App Store-safe.
    public static func random(byteCount: Int = 32) -> PolymorphismSeed {
        precondition(byteCount >= 16)
        var rng = SystemRandomNumberGenerator()
        var bytes = [UInt8]()
        bytes.reserveCapacity(byteCount)
        for _ in 0..<byteCount {
            bytes.append(UInt8.random(in: 0...255, using: &rng))
        }
        return PolymorphismSeed(bytes: bytes)
    }

    /// Resolves the seed for a build.
    ///
    /// CI sets `KSEAL_BUILD_SEED` (hex) to make a build's polymorphism auditable
    /// and reproducible; otherwise a fresh random seed is drawn. This keeps
    /// reproducible-build pipelines deterministic while defaulting to per-build
    /// randomness.
    public static func resolve(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        byteCount: Int = 32
    ) -> PolymorphismSeed {
        if let hex = environment["KSEAL_BUILD_SEED"], let seed = PolymorphismSeed(hex: hex) {
            return seed
        }
        return random(byteCount: byteCount)
    }

    /// Parses a hex-encoded seed.
    public init?(hex: String) {
        guard let bytes = HexEncoding.decode(hex.trimmingCharacters(in: .whitespacesAndNewlines)),
              bytes.count >= 16 else { return nil }
        self.bytes = bytes
    }

    /// Hex encoding of the raw seed. Handle as a secret.
    public var hex: String { HexEncoding.encode(bytes) }

    /// SHA-256 of the seed, hex encoded. Safe to publish in the build proof.
    public var digestHex: String { SHA256.hexDigest(bytes) }

    /// Derives a deterministic keystream of `length` bytes, domain-separated by
    /// `context`, using SHA-256 in counter mode: block_i = SHA256(seed ‖ context ‖ i).
    ///
    /// Distinct `context` values (e.g. per string index) yield independent
    /// keystreams from the same seed, so reusing the seed across many strings
    /// never reuses keystream material.
    public func keystream(length: Int, context: String) -> [UInt8] {
        guard length > 0 else { return [] }
        var out = [UInt8]()
        out.reserveCapacity(length)
        var counter: UInt64 = 0
        let prefix = bytes + Array(context.utf8)
        while out.count < length {
            var block = prefix
            for shift in stride(from: 56, through: 0, by: -8) {
                block.append(UInt8((counter >> UInt64(shift)) & 0xff))
            }
            out.append(contentsOf: SHA256.hash(block))
            counter += 1
        }
        return Array(out.prefix(length))
    }
}
