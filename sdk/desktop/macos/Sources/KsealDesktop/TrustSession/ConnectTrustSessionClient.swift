import Foundation

/// Connection settings for the trust-session client.
public struct TrustSessionConfig: Sendable {
    /// Base URL of the kseal device-plane endpoint (e.g. `https://edge.kseal.io`).
    public var baseURL: URL
    public var tenantId: String
    public var appId: String
    /// Reported platform discriminant (see `Platform`).
    public var platform: Platform

    public init(baseURL: URL, tenantId: String, appId: String, platform: Platform = .desktopMac) {
        self.baseURL = baseURL
        self.tenantId = tenantId
        self.appId = appId
        self.platform = platform
    }
}

/// `TrustSessionClient` over the Connect protocol (https://connectrpc.com).
///
/// Unary calls are plain HTTP POSTs to `/<package>.<Service>/<Method>`:
/// - `GetNonce` / `VerifyAttestation` use Connect's JSON codec (proto3 JSON
///   mapping: `int64`/`uint64` as strings, `bytes` as base64, enums as names).
/// - `ValidateRequestProof` forwards the core-produced `RequestProof` protobuf
///   bytes verbatim using the binary codec, so the server validates exactly the
///   signature the core computed (no re-encoding, no field drift).
public final class ConnectTrustSessionClient: TrustSessionClient {
    private let config: TrustSessionConfig
    private let transport: HTTPTransport

    private static let trustService = "kseal.v1.TrustService"

    public init(config: TrustSessionConfig, transport: HTTPTransport = URLSessionTransport()) {
        self.config = config
        self.transport = transport
    }

    public func getNonce() throws -> Data {
        let body: [String: Any] = [
            "tenantId": config.tenantId,
            "appId": config.appId,
            "platform": ProtoJSON.platformName(config.platform),
        ]
        let json = try call("GetNonce", jsonBody: body)
        guard let b64 = json["nonce"] as? String, let nonce = Data(base64Encoded: b64), !nonce.isEmpty else {
            throw TrustSessionError(message: "GetNonce response missing nonce")
        }
        return nonce
    }

    public func verifyAttestation(
        nonce: Data,
        riskBitset: UInt64,
        buildHash: String,
        policyHash: String,
        instanceId: String,
        attestationToken: Data
    ) throws -> TrustSession {
        var body: [String: Any] = [
            "tenantId": config.tenantId,
            "appId": config.appId,
            "buildHash": buildHash,
            "policyHash": policyHash,
            // proto3 JSON encodes 64-bit integers as strings.
            "riskBitset": String(riskBitset),
            "nonce": nonce.base64EncodedString(),
            "platform": ProtoJSON.platformName(config.platform),
            "instanceId": instanceId,
        ]
        if !attestationToken.isEmpty {
            body["platformAttestationToken"] = attestationToken.base64EncodedString()
        }

        let json = try call("VerifyAttestation", jsonBody: body)
        let token = json["trustToken"] as? [String: Any] ?? [:]
        return TrustSession(
            tokenId: token["tokenId"] as? String ?? "",
            signedToken: ProtoJSON.base64(json["signedToken"]),
            accepted: json["accepted"] as? Bool ?? false,
            rejectionReason: json["rejectionReason"] as? String ?? "",
            expiresAt: ProtoJSON.int64(token["expiresAt"]),
            riskLevel: ProtoJSON.trustLevel(token["riskLevel"]),
            capabilityScopes: token["capabilityScope"] as? [String] ?? []
        )
    }

    public func validateRequestProof(_ proof: RequestProof) throws -> RequestProofDecision {
        let response = try post("ValidateRequestProof", contentType: "application/proto", body: proof.proofBytes)
        guard response.status == 200 else {
            throw TrustSessionError(message: "ValidateRequestProof failed: HTTP \(response.status)")
        }
        let result = try RequestProofResultProto.decode(response.body)
        return RequestProofDecision(decision: result.decision, reason: result.reason)
    }

    // MARK: - Transport plumbing

    private func call(_ method: String, jsonBody: [String: Any]) throws -> [String: Any] {
        let body = try JSONSerialization.data(withJSONObject: jsonBody, options: [])
        let response = try post(method, contentType: "application/json", body: body)
        guard response.status == 200 else {
            throw TrustSessionError(message: "\(method) failed: \(ConnectError.describe(response))")
        }
        guard let object = try JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
            throw TrustSessionError(message: "\(method) returned a non-object JSON body")
        }
        return object
    }

    private func post(_ method: String, contentType: String, body: Data) throws -> HTTPResponse {
        let url = config.baseURL
            .appendingPathComponent(Self.trustService)
            .appendingPathComponent(method)
        let headers = [
            "Content-Type": contentType,
            "Connect-Protocol-Version": "1",
            "Accept": contentType,
        ]
        return try transport.post(url: url, headers: headers, body: body)
    }
}

/// proto3-JSON value helpers (lenient: tolerates omitted/zero defaults).
enum ProtoJSON {
    static func platformName(_ platform: Platform) -> String {
        switch platform {
        case .android: return "PLATFORM_ANDROID"
        case .ios: return "PLATFORM_IOS"
        case .unspecified: return "PLATFORM_UNSPECIFIED"
        }
    }

    /// proto3 JSON encodes `int64` either as a quoted string or (some encoders)
    /// a bare number; accept both, defaulting to 0 when absent.
    static func int64(_ value: Any?) -> Int64 {
        if let s = value as? String { return Int64(s) ?? 0 }
        if let n = value as? NSNumber { return n.int64Value }
        return 0
    }

    /// Decodes a proto3-JSON `bytes` field (base64 string) to `Data`.
    static func base64(_ value: Any?) -> Data {
        guard let s = value as? String, let data = Data(base64Encoded: s) else { return Data() }
        return data
    }

    static func trustLevel(_ value: Any?) -> TrustLevel {
        switch value as? String {
        case "TRUST_LEVEL_TRUSTED": return .trusted
        case "TRUST_LEVEL_LOW_RISK": return .lowRisk
        case "TRUST_LEVEL_MEDIUM_RISK": return .mediumRisk
        case "TRUST_LEVEL_HIGH_RISK": return .highRisk
        case "TRUST_LEVEL_CRITICAL": return .critical
        default:
            // Some encoders emit the numeric discriminant.
            if let n = value as? NSNumber { return TrustLevel(code: n.int32Value) }
            return .unspecified
        }
    }
}

/// Renders a Connect error body for diagnostics (no PII; codes/messages only).
enum ConnectError {
    static func describe(_ response: HTTPResponse) -> String {
        if let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
           let code = object["code"] as? String {
            let message = object["message"] as? String ?? ""
            return "HTTP \(response.status) [\(code)] \(message)"
        }
        return "HTTP \(response.status)"
    }
}
