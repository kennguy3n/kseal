import Foundation
import Dispatch
import CKseal

/// Weighted risk score plus the confidence the core derived for it.
struct CoreRiskScore {
    let score: UInt32
    let confidence: Confidence
}

/// Typed classification for every error the kseal SDK can raise. Callers branch
/// on `kind` (a stable, exhaustive enum) instead of parsing a message string.
///
/// The FFI-backed cases mirror the trust core's C ABI status codes one-to-one
/// (see `kseal.h` / `Status` in `kseal-ffi`); the remaining cases describe
/// SDK-level precondition failures that never reach the core.
public enum KsealErrorKind: Equatable, Sendable {
    /// A request proof was requested before a trust token was set; complete
    /// attestation and call `setTrustToken(_:)` first.
    case trustTokenMissing
    /// The trust core could not be created (e.g. malformed key arguments).
    case coreInitializationFailed
    /// A signed config was rejected (bad signature, rollback, or decode failure).
    case configRejected
    /// An argument was null or otherwise invalid at the FFI boundary.
    case invalidArgument
    /// A protobuf payload failed to decode.
    case decodeFailed
    /// A cryptographic operation failed.
    case cryptoFailed
    /// Serialization/compression on the telemetry transport path failed.
    case transportFailed
    /// An unexpected internal failure (should not occur in normal operation).
    case internalError

    /// Maps a raw FFI status code (`kseal-ffi` `Status`) to a typed kind.
    public init(status: Int32) {
        switch status {
        case -1, -3: self = .invalidArgument // ErrNull, ErrInvalid
        case -2: self = .decodeFailed // ErrDecode
        case -4: self = .cryptoFailed // ErrCrypto
        case -5: self = .transportFailed // ErrTransport
        default: self = .internalError // ErrPanic / unknown
        }
    }
}

/// Error raised by the kseal SDK.
///
/// Carries a typed ``KsealErrorKind`` for branching plus a human-readable
/// `message` for logs/diagnostics. Messages never contain PII.
public struct TrustCoreError: Error, CustomStringConvertible, LocalizedError, Equatable {
    /// Typed classification of the failure; switch on this rather than the message.
    public let kind: KsealErrorKind
    /// Diagnostic detail (safe to log; contains no PII).
    public let message: String

    public init(kind: KsealErrorKind, message: String) {
        self.kind = kind
        self.message = message
    }

    /// FFI call-site convenience: derives ``kind`` from the C ABI status code.
    init(status: Int32, message: String) {
        self.init(kind: KsealErrorKind(status: status), message: message)
    }

    public var description: String { message }
    public var errorDescription: String? { message }
}

/// High-level handle to the Rust trust core, hiding the raw FFI surface.
///
/// The production implementation, `NativeTrustCore`, delegates to the real Rust
/// core over the C ABI; there is no stubbed core — tests run the same
/// implementation against a host build of the library.
protocol TrustCore: AnyObject {
    var version: String { get }
    func loadConfig(_ signedConfigBytes: Data) throws
    func tryLoadConfig(_ signedConfigBytes: Data) -> Bool
    func evaluateRisk(_ riskBits: UInt64) throws -> CoreRiskScore
    func computeRiskLevel(_ riskBits: UInt64) -> TrustLevel
    /// Scores `riskBits` and derives its trust level atomically, so a concurrent
    /// config swap cannot split the two across different policies.
    func evaluateRiskAndLevel(_ riskBits: UInt64) throws -> (CoreRiskScore, TrustLevel)
    func createEvent(
        eventType: EventType,
        riskBits: UInt64,
        confidence: Confidence,
        buildHash: String,
        policyHash: String,
        installKeyHash: String,
        coarseTimeBucket: Int64,
        country: String?
    ) throws -> Data
    func batchAndCompress(_ events: [Data]) throws -> Data
    func generateRequestProof(tokenId: String, requestHash: Data, nonce: Data, sequence: Int64) throws -> Data
    func generateNonce(_ length: Int) throws -> Data
    func compress(_ data: Data, level: Int32) throws -> Data
    func decompress(_ data: Data) throws -> Data
    /// The active policy's opt-in re-attestation cadence in seconds, or 0 when
    /// continuous mode is off / no policy is loaded. Local read only.
    func reattestIntervalSecs() -> UInt32
    /// Maps `riskBits` to a trust `Decision` using the exact mapping the server
    /// applies (`risk.Decision`). `.allow` when no policy is loaded.
    func decision(_ riskBits: UInt64) -> Decision
    /// Verifies + applies a serialized `kseal.v1.SignedKillSwitch`; returns the
    /// resulting killed state. Fail-safe: a forged/absent command never disables
    /// the app, only an Ed25519-valid `DISABLE` does (a valid `ENABLE` lifts it).
    func applyKillSwitch(_ signedKillSwitchBytes: Data) -> Bool
    /// Whether a valid kill switch currently disables the app (fail-safe state).
    func isKilled() -> Bool
}

/// Verifies an Ed25519 signature over `config` bytes (stateless helper).
func verifyConfigSignature(config: Data, signature: Data, publicKey: Data) -> Bool {
    config.withUnsafeBytes { c in
        signature.withUnsafeBytes { s in
            publicKey.withUnsafeBytes { p in
                kseal_verify_config_signature(
                    c.bindMemory(to: UInt8.self).baseAddress, UInt(c.count),
                    s.bindMemory(to: UInt8.self).baseAddress, UInt(s.count),
                    p.bindMemory(to: UInt8.self).baseAddress, UInt(p.count)
                ) == 1
            }
        }
    }
}

/// Real trust core backed by the Rust `kseal-ffi` C ABI.
///
/// Owns an opaque core handle for its lifetime; `deinit` releases it (the last
/// strong reference is dropped only when no call is in flight).
///
/// Thread-safety mirrors the Rust borrow semantics of the C ABI: config mutation
/// (`kseal_load_config` takes `&mut`) runs as a barrier on `coreQueue`, while the
/// read paths (`&self`: risk evaluation, event/proof creation) run as concurrent
/// syncs and may proceed in parallel. `generateNonce`/`compress`/`decompress`
/// are stateless (no core handle) and bypass the queue.
final class NativeTrustCore: TrustCore {

    private let handle: OpaquePointer
    private let coreQueue = DispatchQueue(label: "io.kseal.core", attributes: .concurrent)

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        kseal_core_free(handle)
    }

    /// Creates a core instance.
    ///
    /// - Parameters:
    ///   - configPublicKey: Ed25519 public key (32 bytes) used to verify signed configs.
    ///   - proofKey: instance HMAC key for request proofs (Keychain/Secure-Enclave-bound in production).
    ///   - maxBatchEvents/riskWindow/zstdLevel: 0 selects the core defaults.
    static func create(
        configPublicKey: Data,
        proofKey: Data,
        platform: Platform = .ios,
        maxBatchEvents: Int = 0,
        riskWindow: Int = 0,
        zstdLevel: Int32 = 0
    ) throws -> NativeTrustCore {
        let handle: OpaquePointer? = configPublicKey.withUnsafeBytes { pk in
            proofKey.withUnsafeBytes { proof in
                kseal_core_new(
                    pk.bindMemory(to: UInt8.self).baseAddress, UInt(pk.count),
                    proof.bindMemory(to: UInt8.self).baseAddress, UInt(proof.count),
                    platform.rawValue,
                    UInt(max(0, maxBatchEvents)),
                    UInt(max(0, riskWindow)),
                    zstdLevel
                )
            }
        }
        guard let handle else {
            throw TrustCoreError(kind: .coreInitializationFailed, message: "failed to create trust core (bad key arguments?)")
        }
        return NativeTrustCore(handle: handle)
    }

    var version: String {
        guard let cstr = kseal_version() else { return "" }
        return String(cString: cstr)
    }

    func loadConfig(_ signedConfigBytes: Data) throws {
        try coreQueue.sync(flags: .barrier) {
            let status = signedConfigBytes.withUnsafeBytes { b in
                kseal_load_config(handle, b.bindMemory(to: UInt8.self).baseAddress, UInt(b.count))
            }
            if status != 0 {
                throw TrustCoreError(kind: .configRejected, message: "loadConfig failed: status=\(status)")
            }
        }
    }

    func tryLoadConfig(_ signedConfigBytes: Data) -> Bool {
        coreQueue.sync(flags: .barrier) {
            signedConfigBytes.withUnsafeBytes { b in
                kseal_load_config(handle, b.bindMemory(to: UInt8.self).baseAddress, UInt(b.count)) == 0
            }
        }
    }

    func evaluateRisk(_ riskBits: UInt64) throws -> CoreRiskScore {
        try coreQueue.sync { try unsafeEvaluateRisk(riskBits) }
    }

    func computeRiskLevel(_ riskBits: UInt64) -> TrustLevel {
        coreQueue.sync { unsafeComputeRiskLevel(riskBits) }
    }

    func evaluateRiskAndLevel(_ riskBits: UInt64) throws -> (CoreRiskScore, TrustLevel) {
        // One dispatch keeps score and level on the same policy; a config swap
        // (barrier write) cannot interleave between the two FFI reads.
        try coreQueue.sync { (try unsafeEvaluateRisk(riskBits), unsafeComputeRiskLevel(riskBits)) }
    }

    // `coreQueue.sync` is non-reentrant, so the on-queue work lives in these
    // helpers that the combined and single-shot entry points share.
    private func unsafeEvaluateRisk(_ riskBits: UInt64) throws -> CoreRiskScore {
        var score: UInt32 = 0
        var confidence: Int32 = 0
        let status = kseal_evaluate_risk(handle, riskBits, &score, &confidence)
        if status != 0 {
            throw TrustCoreError(status: status, message: "evaluateRisk failed: status=\(status)")
        }
        return CoreRiskScore(score: score, confidence: Confidence(code: confidence))
    }

    private func unsafeComputeRiskLevel(_ riskBits: UInt64) -> TrustLevel {
        TrustLevel(code: kseal_compute_risk_level(handle, riskBits))
    }

    func createEvent(
        eventType: EventType,
        riskBits: UInt64,
        confidence: Confidence,
        buildHash: String,
        policyHash: String,
        installKeyHash: String,
        coarseTimeBucket: Int64,
        country: String?
    ) throws -> Data {
        try coreQueue.sync {
            var out = KsealBuffer()
            let status = buildHash.withCString { build in
                policyHash.withCString { policy in
                    installKeyHash.withCString { install in
                        withOptionalCString(country) { countryPtr in
                            kseal_create_event(
                                handle,
                                eventType.rawValue,
                                riskBits,
                                confidence.rawValue,
                                build, policy, install,
                                coarseTimeBucket,
                                countryPtr,
                                &out
                            )
                        }
                    }
                }
            }
            if status != 0 {
                kseal_buffer_free(out)
                throw TrustCoreError(status: status, message: "createEvent failed: status=\(status)")
            }
            return Self.consume(&out)
        }
    }

    func batchAndCompress(_ events: [Data]) throws -> Data {
        try coreQueue.sync {
            var out = KsealBuffer()
            let status = withBytesViews(events) { views in
                kseal_batch_and_compress(handle, views.baseAddress, UInt(views.count), &out)
            }
            if status != 0 {
                kseal_buffer_free(out)
                throw TrustCoreError(status: status, message: "batchAndCompress failed: status=\(status)")
            }
            return Self.consume(&out)
        }
    }

    func generateRequestProof(tokenId: String, requestHash: Data, nonce: Data, sequence: Int64) throws -> Data {
        try coreQueue.sync {
            var out = KsealBuffer()
            let status = tokenId.withCString { tok in
                requestHash.withUnsafeBytes { rh in
                    nonce.withUnsafeBytes { nc in
                        kseal_generate_request_proof(
                            handle,
                            tok,
                            rh.bindMemory(to: UInt8.self).baseAddress, UInt(rh.count),
                            nc.bindMemory(to: UInt8.self).baseAddress, UInt(nc.count),
                            sequence,
                            &out
                        )
                    }
                }
            }
            if status != 0 {
                kseal_buffer_free(out)
                throw TrustCoreError(status: status, message: "generateRequestProof failed: status=\(status)")
            }
            return Self.consume(&out)
        }
    }

    func generateNonce(_ length: Int) throws -> Data {
        var out = KsealBuffer()
        let status = kseal_generate_nonce(UInt(max(0, length)), &out)
        if status != 0 {
            kseal_buffer_free(out)
            throw TrustCoreError(status: status, message: "generateNonce failed: status=\(status)")
        }
        return Self.consume(&out)
    }

    func compress(_ data: Data, level: Int32 = 0) throws -> Data {
        var out = KsealBuffer()
        let status = data.withUnsafeBytes { b in
            kseal_compress(b.bindMemory(to: UInt8.self).baseAddress, UInt(b.count), level, &out)
        }
        if status != 0 {
            kseal_buffer_free(out)
            throw TrustCoreError(status: status, message: "compress failed: status=\(status)")
        }
        return Self.consume(&out)
    }

    func decompress(_ data: Data) throws -> Data {
        var out = KsealBuffer()
        let status = data.withUnsafeBytes { b in
            kseal_decompress(b.bindMemory(to: UInt8.self).baseAddress, UInt(b.count), &out)
        }
        if status != 0 {
            kseal_buffer_free(out)
            throw TrustCoreError(status: status, message: "decompress failed: status=\(status)")
        }
        return Self.consume(&out)
    }

    func reattestIntervalSecs() -> UInt32 {
        coreQueue.sync {
            // A negative status means no handle/policy; treat as continuous-off.
            let v = kseal_reattest_interval_secs(handle)
            return v < 0 ? 0 : UInt32(truncatingIfNeeded: v)
        }
    }

    func decision(_ riskBits: UInt64) -> Decision {
        coreQueue.sync {
            // A negative status is an internal error; fail open (.allow) so the
            // SDK never blocks the host on its own.
            let code = kseal_decision(handle, riskBits)
            return code < 0 ? .allow : Decision(code: code)
        }
    }

    func applyKillSwitch(_ signedKillSwitchBytes: Data) -> Bool {
        // State mutation: run as a barrier, like config swaps.
        coreQueue.sync(flags: .barrier) {
            signedKillSwitchBytes.withUnsafeBytes { b in
                // 1 = killed; 0 / negative leaves the app available (fail-safe).
                kseal_apply_kill_switch(handle, b.bindMemory(to: UInt8.self).baseAddress, UInt(b.count)) == 1
            }
        }
    }

    func isKilled() -> Bool {
        coreQueue.sync { kseal_is_killed(handle) == 1 }
    }

    /// Copies a core-owned buffer into a `Data` and releases the original.
    private static func consume(_ buffer: inout KsealBuffer) -> Data {
        defer { kseal_buffer_free(buffer) }
        guard let data = buffer.data, buffer.len > 0 else { return Data() }
        return Data(bytes: data, count: Int(buffer.len))
    }
}

/// Runs `body` with a contiguous array of `KsealBytesView` over `datas`,
/// keeping each `Data`'s storage pinned for the duration of the call.
private func withBytesViews<R>(_ datas: [Data], _ body: (UnsafeBufferPointer<KsealBytesView>) -> R) -> R {
    func recurse(_ index: Int, _ acc: inout [KsealBytesView]) -> R {
        if index == datas.count {
            return acc.withUnsafeBufferPointer(body)
        }
        return datas[index].withUnsafeBytes { raw in
            acc.append(KsealBytesView(data: raw.bindMemory(to: UInt8.self).baseAddress, len: UInt(raw.count)))
            return recurse(index + 1, &acc)
        }
    }
    var acc: [KsealBytesView] = []
    acc.reserveCapacity(datas.count)
    return recurse(0, &acc)
}

/// Calls `body` with a C string for `value`, or `nil` when `value` is `nil`.
private func withOptionalCString<R>(_ value: String?, _ body: (UnsafePointer<CChar>?) -> R) -> R {
    if let value {
        return value.withCString { body($0) }
    }
    return body(nil)
}
