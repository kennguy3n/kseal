import Foundation
import CryptoKit
import KsealSDK

// Minimal end-to-end quickstart:
//
//   initialize → evaluateRisk → GetNonce → attestation → VerifyAttestation
//              → setTrustToken → getRequestProof → ValidateRequestProof
//
// The SDK calls are real; only the EXTERNAL attestation provider (Apple App
// Attest / DeviceCheck) is swappable. The host owns transport (KsealTrustClient).

let env = ProcessInfo.processInfo.environment
let tenantId = env["KSEAL_TENANT"] ?? "acme"
let appId = env["KSEAL_APP"] ?? "com.acme.app"
let apiKey = env["KSEAL_API_KEY"] ?? ""
let endpoint = env["KSEAL_ENDPOINT"] ?? "http://localhost:8080"
guard let baseURL = URL(string: endpoint) else {
    FileHandle.standardError.write(Data("invalid KSEAL_ENDPOINT: \(endpoint)\n".utf8))
    exit(2)
}

// MARK: - External attestation provider (the one mocked dependency)

protocol AttestationTokenProvider {
    func attestationToken(nonce: Data) throws -> Data
}

/// Local-dev fake. Apple App Attest/DeviceCheck only works on a real device, so
/// off-device this returns a placeholder a stock server (correctly) rejects —
/// fail-closed. On-device, implement this with `DCAppAttestService`.
struct DevAttestationTokenProvider: AttestationTokenProvider {
    func attestationToken(nonce: Data) throws -> Data {
        Data(("dev-attestation:" + nonce.base64EncodedString()).utf8)
    }
}

// MARK: - Stable install identity

/// Returns a stable, non-PII install id persisted across runs, mirroring the
/// Android sample's SharedPreferences-backed id. The production SDK derives a
/// tenant-scoped install identity internally; here the host owns the id since it
/// drives the transport directly, so persist it rather than minting a new one
/// each run (which would create a fresh trust session identity every time).
func stableInstanceId() -> String {
    let fm = FileManager.default
    let base = (try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true))
        ?? URL(fileURLWithPath: NSTemporaryDirectory())
    let dir = base.appendingPathComponent("kseal-quickstart", isDirectory: true)
    try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
    let file = dir.appendingPathComponent("instance-id")
    if let id = try? String(contentsOf: file, encoding: .utf8), !id.isEmpty {
        return id
    }
    let id = UUID().uuidString
    try? id.write(to: file, atomically: true, encoding: .utf8)
    return id
}

// MARK: - Host-owned transport over the TrustService RPCs

enum TrustError: Error, CustomStringConvertible {
    case http(String)
    var description: String { if case let .http(m) = self { return m }; return "trust error" }
}

struct TrustSession { let accepted: Bool; let tokenId: String; let rejectionReason: String }

struct KsealTrustClient {
    let baseURL: URL
    let tenantId: String
    let appId: String

    /// Builds the RPC URL by string. Connect paths contain a '/' (Service/Method);
    /// `appendingPathComponent` is meant for a single segment and percent-encodes
    /// the '/' to %2F on some Foundation versions (e.g. swift-corelibs on Linux),
    /// so concatenate instead — this matches the Android client and is correct
    /// across platforms.
    private func rpcURL(_ method: String) -> URL {
        let base = baseURL.absoluteString
        let trimmed = base.hasSuffix("/") ? String(base.dropLast()) : base
        return URL(string: "\(trimmed)/kseal.v1.\(method)")!
    }

    /// Synchronous POST: a deliberate simplification so this CLI reads top-to-
    /// bottom. `URLSession.shared` runs its completion on a background delegate
    /// queue (not the main queue), so the wait doesn't deadlock here — but a real
    /// app should NOT block the calling thread: use the async API instead, e.g.
    /// `let (data, resp) = try await URLSession.shared.data(for: req)`.
    private func post(_ method: String, body: Data, contentType: String) throws -> Data {
        var req = URLRequest(url: rpcURL(method))
        req.httpMethod = "POST"
        req.setValue(contentType, forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        let sem = DispatchSemaphore(value: 0)
        var out: Data?; var status = 0; var err: Error?
        URLSession.shared.dataTask(with: req) { data, resp, e in
            out = data; status = (resp as? HTTPURLResponse)?.statusCode ?? 0; err = e; sem.signal()
        }.resume()
        sem.wait()
        if let err { throw TrustError.http("\(method): \(err)") }
        let data = out ?? Data()
        guard (200..<300).contains(status) else {
            throw TrustError.http("\(method) failed (\(status)): \(String(decoding: data, as: UTF8.self))")
        }
        return data
    }

    func getNonce() throws -> Data {
        let body = try JSONSerialization.data(withJSONObject: [
            "tenant_id": tenantId, "app_id": appId, "platform": "PLATFORM_IOS",
        ])
        let resp = try post("TrustService/GetNonce", body: body, contentType: "application/json")
        let obj = try JSONSerialization.jsonObject(with: resp) as? [String: Any]
        guard let s = obj?["nonce"] as? String, let nonce = Data(base64Encoded: s) else {
            throw TrustError.http("GetNonce: missing nonce")
        }
        return nonce
    }

    func verifyAttestation(nonce: Data, buildHash: String, instanceId: String, token: Data) throws -> TrustSession {
        let body = try JSONSerialization.data(withJSONObject: [
            "tenant_id": tenantId, "app_id": appId, "platform": "PLATFORM_IOS",
            "nonce": nonce.base64EncodedString(), "build_hash": buildHash,
            "instance_id": instanceId, "platform_attestation_token": token.base64EncodedString(),
        ])
        let resp = try post("TrustService/VerifyAttestation", body: body, contentType: "application/json")
        // Connect serializes proto as JSON with camelCase field names
        // (protojson default): trustToken/tokenId/rejectionReason.
        let obj = (try JSONSerialization.jsonObject(with: resp) as? [String: Any]) ?? [:]
        let tokenId = (obj["trustToken"] as? [String: Any])?["tokenId"] as? String ?? ""
        return TrustSession(
            accepted: obj["accepted"] as? Bool ?? false,
            tokenId: tokenId,
            rejectionReason: obj["rejectionReason"] as? String ?? ""
        )
    }

    /// Posts the SDK's serialized RequestProof as binary proto and reads the
    /// `decision` enum (field 1 varint) from the RequestProofResult.
    func validateRequestProof(_ proofBytes: Data) throws -> String {
        let resp = try post("TrustService/ValidateRequestProof", body: proofBytes, contentType: "application/proto")
        return Self.parseDecision(resp)
    }

    static func parseDecision(_ bytes: Data) -> String {
        let b = [UInt8](bytes)
        var i = 0, decision = 0
        while i < b.count {
            let tag = Int(b[i]); i += 1
            let field = tag >> 3
            switch tag & 0x7 {
            case 0:
                var shift = 0, v = 0
                while i < b.count { let x = Int(b[i]); i += 1; v |= (x & 0x7f) << shift; if x & 0x80 == 0 { break }; shift += 7 }
                if field == 1 { decision = v }
            case 2:
                var shift = 0, len = 0
                while i < b.count { let x = Int(b[i]); i += 1; len |= (x & 0x7f) << shift; if x & 0x80 == 0 { break }; shift += 7 }
                i += len
            case 1: i += 8   // fixed64 — skip so an added wide field can't stall the scan
            case 5: i += 4   // fixed32 — skip
            default: i = b.count  // group/unknown wire type — stop
            }
        }
        switch decision { case 1: return "ALLOW"; case 2: return "STEP_UP"; case 3: return "DENY"; default: return "UNSPECIFIED" }
    }
}

// MARK: - Flow

print("kseal iOS quickstart — tenant=\(tenantId) app=\(appId) endpoint=\(baseURL)")

let sdk = try KsealSDK.initialize(tenantId: tenantId, appId: appId, apiKey: apiKey,
                                  options: .init(buildHash: "sha256:dev-build"))

let risk = try sdk.evaluateRisk()
print("[risk] trustLevel=\(risk.trustLevel) score=\(risk.score) clean=\(risk.isClean) signals=\(risk.signals.count)")

let client = KsealTrustClient(baseURL: baseURL, tenantId: tenantId, appId: appId)
let provider: AttestationTokenProvider = DevAttestationTokenProvider()

do {
    let nonce = try client.getNonce()
    print("[nonce] \(nonce.count) bytes")
    let token = try provider.attestationToken(nonce: nonce)
    let instanceId = stableInstanceId()
    let session = try client.verifyAttestation(nonce: nonce, buildHash: "sha256:dev-build", instanceId: instanceId, token: token)
    if session.accepted {
        print("[trust] accepted token=\(session.tokenId.prefix(8))…")
        // setTrustToken takes the trust-token id (a UUID): it becomes RequestProof.trustTokenId,
        // which the server resolves as a UUID for session lookup. The proof HMAC key is the SDK's
        // instance key, set at init — not the signed JWT. Mirrors the desktop SDK's
        // establishTrustSession(), which likewise calls setTrustToken(tokenId).
        sdk.setTrustToken(session.tokenId)
        let requestHash = Data(SHA256.hash(data: Data("POST /v1/orders".utf8)))
        let proof = try sdk.getRequestProof(requestHash: requestHash)
        let decision = try client.validateRequestProof(proof.proofBytes)
        print("[proof] decision=\(decision)")
    } else {
        print("[trust] rejected: \(session.rejectionReason)")
        print("        expected with the dev attestation provider; use App Attest on a real device.")
    }
} catch {
    print("[trust] \(error)")
    print("        start the server with `make docker-up`, then re-run.")
}

sdk.flushTelemetry()
print("done.")
