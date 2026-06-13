import Foundation
import CryptoKit
import KsealDesktop

// Minimal end-to-end desktop quickstart:
//
//   initialize → evaluateRisk (offline) → establishTrustSession → authorizeRequest
//
// It mirrors the documented macOS integration in docs/desktop-sdk.md. The only
// mocked dependency is the EXTERNAL platform notary: LocalCodeIntegrityAttestor
// builds the attestation token from the process's real code-signing info, so on
// an unsigned dev build the server may reject it — the network steps degrade
// gracefully and print the server's verdict either way.

// Config via env so the sample is copy-paste runnable; sensible local defaults.
let tenantId = ProcessInfo.processInfo.environment["KSEAL_TENANT"] ?? "acme"
let appId = ProcessInfo.processInfo.environment["KSEAL_APP"] ?? "com.acme.app"
let baseURLString = ProcessInfo.processInfo.environment["KSEAL_ENDPOINT"] ?? "http://localhost:8080"

guard let baseURL = URL(string: baseURLString) else {
    FileHandle.standardError.write(Data("invalid KSEAL_ENDPOINT: \(baseURLString)\n".utf8))
    exit(2)
}

func sha256(_ data: Data) -> Data {
    // The server treats request_hash opaquely; only the SDK<->server proof must
    // agree, and the SDK hashes the bytes we pass here, so any stable hash works.
    Data(SHA256.hash(data: data))
}

print("kseal desktop quickstart — tenant=\(tenantId) app=\(appId) endpoint=\(baseURL)")

// 1. Initialize once (no network).
let kseal = try KsealDesktop.initialize(
    tenantId: tenantId,
    appId: appId,
    options: .init(buildHash: "sha256:dev-build")
)

// 2. Evaluate local integrity (offline, cheap).
let assessment = try kseal.evaluateRisk()
print("[risk] trustLevel=\(assessment.trustLevel) score=\(assessment.score) confidence=\(assessment.confidence) clean=\(assessment.isClean)")

// 3. Establish a trust session (the SDK's only network call).
let client = ConnectTrustSessionClient(config: .init(baseURL: baseURL, tenantId: tenantId, appId: appId))
do {
    let session = try kseal.establishTrustSession(using: client)
    if session.accepted {
        print("[trust] session accepted — token=\(session.tokenId.prefix(8))… riskLevel=\(session.riskLevel)")

        // 4. Bind a protected request to the trust token and get the decision.
        let requestHash = sha256(Data("POST /v1/orders".utf8))
        let decision = try kseal.authorizeRequest(requestHash: requestHash, using: client)
        print("[proof] decision=\(decision.decision.rawValue) reason=\(decision.reason)")
    } else {
        print("[trust] session rejected: \(session.rejectionReason)")
        print("        (expected for an unsigned/dev build — sign + notarize, or use a dev server that accepts the dev attestor)")
    }
} catch {
    print("[trust] could not reach the server at \(baseURL): \(error)")
    print("        start it with `make docker-up` from the repo root, then re-run.")
}

kseal.flushTelemetry()
print("done.")
