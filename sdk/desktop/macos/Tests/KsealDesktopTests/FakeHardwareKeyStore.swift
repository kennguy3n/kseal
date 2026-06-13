import Foundation
@testable import KsealDesktop

/// Deterministic stand-in for a hardware-backed key store, used to exercise the
/// proof-key sealing/migration logic on any host. `seal` prepends a magic header
/// and XOR-obfuscates the payload; `unseal` validates the header so a foreign /
/// legacy-raw blob fails to unseal exactly like a real wrong-device ciphertext.
final class FakeHardwareKeyStore: HardwareKeyStore {
    static let magic: [UInt8] = [0x4B, 0x53, 0x45, 0x41] // "KSEA"
    private let mask: UInt8

    let isHardwareBacked: Bool

    init(isHardwareBacked: Bool = true, mask: UInt8 = 0x5A) {
        self.isHardwareBacked = isHardwareBacked
        self.mask = mask
    }

    func seal(_ plaintext: Data) throws -> Data {
        var out = Data(Self.magic)
        out.append(contentsOf: plaintext.map { $0 ^ mask })
        return out
    }

    func unseal(_ sealed: Data) throws -> Data {
        guard sealed.count >= Self.magic.count,
              Array(sealed.prefix(Self.magic.count)) == Self.magic else {
            throw HardwareKeyStoreError(message: "not sealed by this store")
        }
        return Data(sealed.dropFirst(Self.magic.count).map { $0 ^ mask })
    }
}

/// A store whose seal always fails, to drive the graceful software-degradation
/// path in the proof-key provider.
final class FailingHardwareKeyStore: HardwareKeyStore {
    let isHardwareBacked = true
    func seal(_ plaintext: Data) throws -> Data {
        throw HardwareKeyStoreError(message: "seal unavailable")
    }
    func unseal(_ sealed: Data) throws -> Data {
        throw HardwareKeyStoreError(message: "unseal unavailable")
    }
}
