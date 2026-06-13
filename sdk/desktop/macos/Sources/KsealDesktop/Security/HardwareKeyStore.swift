import Foundation
#if canImport(Security)
import Security
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Binds at-rest key material to a hardware-backed key where the platform offers
/// one, with a clean software fallback. The request-proof HMAC key is sealed
/// before it is persisted, so the on-disk secret cannot be lifted and replayed
/// from another device — yet the **request-proof byte layout is unchanged**: the
/// core still computes `HMAC(proofKey, …)`; only how `proofKey` is protected at
/// rest changes.
///
/// Production binds to the macOS Keychain (Secure-Enclave-wrapped on Apple
/// silicon). This is the **external secure-element mock boundary**: tests inject
/// a fake store so the proof-binding logic is exercised deterministically on any
/// host.
public protocol HardwareKeyStore {
    /// Whether sealed blobs are bound to a hardware-backed key (vs. a software
    /// fallback). Surfaced so a policy can require hardware binding and fail
    /// closed when it is unavailable.
    var isHardwareBacked: Bool { get }

    /// Wraps `plaintext` into an opaque blob safe to persist. Throws if the
    /// hardware element rejects the operation.
    func seal(_ plaintext: Data) throws -> Data

    /// Unwraps a blob previously produced by `seal`. Throws if the blob was not
    /// produced by this store / device (tamper or wrong-device).
    func unseal(_ sealed: Data) throws -> Data
}

/// Raised when a hardware key operation cannot complete.
public struct HardwareKeyStoreError: Error, CustomStringConvertible {
    public let message: String
    public var description: String { message }
}

/// Transparent software fallback: the "sealed" blob is the plaintext, so the
/// persisted key is identical to the portable file-backed default. Used when no
/// hardware element is available (e.g. CI, virtualized hosts). `isHardwareBacked`
/// is false so callers can require hardware and fail closed when configured to.
public struct SoftwareKeyStore: HardwareKeyStore {
    public init() {}
    public var isHardwareBacked: Bool { false }
    public func seal(_ plaintext: Data) throws -> Data { plaintext }
    public func unseal(_ sealed: Data) throws -> Data { sealed }
}

/// Returns the production hardware key store for the current platform: a
/// Secure-Enclave/Keychain-wrapped store on macOS, the software fallback
/// elsewhere.
func makeDefaultHardwareKeyStore(label: String) -> HardwareKeyStore {
    #if canImport(Security) && canImport(CryptoKit) && canImport(Darwin)
    if let store = KeychainHardwareKeyStore(label: label) { return store }
    #endif
    return SoftwareKeyStore()
}

#if canImport(Security) && canImport(CryptoKit) && canImport(Darwin)
/// macOS Secure-Enclave-backed key store.
///
/// A non-exportable P-256 key is created in the Secure Enclave
/// (`kSecAttrTokenIDSecureEnclave`) on first use and persisted in the Keychain
/// (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, this-device-only so the
/// secret never syncs or escapes the device). Sealing ECIES-encrypts the proof
/// key to that key's public half; unsealing performs the decryption **inside the
/// Enclave** — the private key material never enters app memory. On hardware
/// without a Secure Enclave the initializer returns nil and the caller falls
/// back to the software store.
///
/// Uses only public Security-framework APIs (App-Store / hardened-runtime safe).
final class KeychainHardwareKeyStore: HardwareKeyStore {

    private let tag: Data
    private let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    /// Returns nil when the Secure Enclave is unavailable (the caller then uses
    /// the software fallback rather than degrading silently).
    init?(label: String) {
        guard SecureEnclave.isAvailable else { return nil }
        self.tag = Data("io.kseal.proofkey.\(label)".utf8)
    }

    var isHardwareBacked: Bool { true }

    func seal(_ plaintext: Data) throws -> Data {
        let privateKey = try loadOrCreateKey()
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw HardwareKeyStoreError(message: "secure-enclave key has no public key")
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw HardwareKeyStoreError(message: "secure-enclave key does not support the seal algorithm")
        }
        var error: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(
            publicKey, algorithm, plaintext as CFData, &error
        ) as Data? else {
            throw HardwareKeyStoreError(message: "seal failed: \(Self.describe(error))")
        }
        return cipher
    }

    func unseal(_ sealed: Data) throws -> Data {
        let privateKey = try loadOrCreateKey()
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw HardwareKeyStoreError(message: "secure-enclave key does not support the unseal algorithm")
        }
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(
            privateKey, algorithm, sealed as CFData, &error
        ) as Data? else {
            throw HardwareKeyStoreError(message: "unseal failed: \(Self.describe(error))")
        }
        return plain
    }

    // MARK: - Key material

    private func loadOrCreateKey() throws -> SecKey {
        if let existing = try loadKey() { return existing }
        return try createKey()
    }

    private func loadKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let ref = item else { return nil }
            // Safe: the query requested a SecKey ref.
            return (ref as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw HardwareKeyStoreError(message: "keychain lookup failed: status=\(status)")
        }
    }

    private func createKey() throws -> SecKey {
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &acError
        ) else {
            throw HardwareKeyStoreError(message: "access control failed: \(Self.describe(acError))")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw HardwareKeyStoreError(message: "secure-enclave key creation failed: \(Self.describe(error))")
        }
        return key
    }

    private static func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error?.takeRetainedValue() else { return "unknown error" }
        return CFErrorCopyDescription(error) as String? ?? "unknown error"
    }
}
#endif
