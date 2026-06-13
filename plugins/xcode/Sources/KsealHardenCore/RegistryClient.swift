import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A minimal HTTP request/response pair so the registry client can run against
/// `URLSession` in production and a deterministic mock in tests.
public struct HTTPRequestSpec: Equatable {
    public var url: URL
    public var method: String
    public var headers: [String: String]
    public var body: Data

    public init(url: URL, method: String, headers: [String: String], body: Data) {
        self.url = url
        self.method = method
        self.headers = headers
        self.body = body
    }
}

public struct HTTPResponseSpec {
    public var statusCode: Int
    public var body: Data

    public init(statusCode: Int, body: Data) {
        self.statusCode = statusCode
        self.body = body
    }
}

public protocol HTTPTransport {
    func send(_ request: HTTPRequestSpec) throws -> HTTPResponseSpec
}

/// `URLSession`-backed transport. Synchronous (semaphore) because the tool runs
/// as a one-shot CLI step in CI.
public struct URLSessionTransport: HTTPTransport {
    private let session: URLSession
    private let timeout: TimeInterval

    public init(session: URLSession = .shared, timeout: TimeInterval = 15) {
        self.session = session
        self.timeout = timeout
    }

    public func send(_ request: HTTPRequestSpec) throws -> HTTPResponseSpec {
        var urlRequest = URLRequest(url: request.url, timeoutInterval: timeout)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = request.body
        for (k, v) in request.headers { urlRequest.setValue(v, forHTTPHeaderField: k) }

        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<HTTPResponseSpec, Error>!
        let task = session.dataTask(with: urlRequest) { data, response, error in
            if let error = error {
                result = .failure(error)
            } else if let http = response as? HTTPURLResponse {
                result = .success(HTTPResponseSpec(statusCode: http.statusCode, body: data ?? Data()))
            } else {
                result = .failure(RegistryError.transport("no HTTP response"))
            }
            semaphore.signal()
        }
        task.resume()
        semaphore.wait()
        return try result.get()
    }
}

/// Configuration for registering a build proof with the control plane.
public struct RegistryConfig {
    public var baseURL: URL
    public var apiKey: String
    public var tenantId: String
    public var appId: String
    public var protectionProfileId: String

    public init(baseURL: URL, apiKey: String, tenantId: String, appId: String, protectionProfileId: String = "") {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.tenantId = tenantId
        self.appId = appId
        self.protectionProfileId = protectionProfileId
    }

    /// Builds a config from environment variables. Returns nil when any required
    /// value is absent, signalling the caller to fall back to offline mode.
    ///
    /// The API key is read from `KSEAL_API_KEY` only — never a flag or a file —
    /// so it is never logged or committed.
    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) -> RegistryConfig? {
        guard let base = env["KSEAL_REGISTRY_URL"], let url = URL(string: base),
              let key = env["KSEAL_API_KEY"], !key.isEmpty,
              let tenant = env["KSEAL_TENANT_ID"], !tenant.isEmpty,
              let app = env["KSEAL_APP_ID"], !app.isEmpty
        else { return nil }
        return RegistryConfig(
            baseURL: url,
            apiKey: key,
            tenantId: tenant,
            appId: app,
            protectionProfileId: env["KSEAL_PROTECTION_PROFILE_ID"] ?? ""
        )
    }
}

public enum RegistryError: Error, CustomStringConvertible {
    case transport(String)
    case httpStatus(Int, String)
    case decode(String)

    public var description: String {
        switch self {
        case .transport(let m): return "registry transport error: \(m)"
        case .httpStatus(let code, let body): return "registry returned HTTP \(code): \(body)"
        case .decode(let m): return "registry response decode error: \(m)"
        }
    }
}

/// Where a build proof ended up.
public enum RegistrationOutcome: Equatable {
    /// Registered with the control plane; carries the server build id.
    case registered(buildId: String)
    /// Network/registry unavailable or unconfigured; proof written to `path`.
    case offline(artifactPath: String)
}

/// Client for `RegistryService.CreateBuild` speaking the Connect **JSON**
/// protocol (`POST {base}/kseal.v1.RegistryService/CreateBuild`).
///
/// proto3-JSON rules are honored: field names are camelCase and the int64
/// `versionCode`/`createdAt` are encoded as strings. Auth uses the same bearer
/// API key the control-plane interceptor expects (`Authorization: Bearer …`).
public struct RegistryClient {
    public static let createBuildPath = "/kseal.v1.RegistryService/CreateBuild"

    private let config: RegistryConfig
    private let transport: HTTPTransport

    public init(config: RegistryConfig, transport: HTTPTransport = URLSessionTransport()) {
        self.config = config
        self.transport = transport
    }

    /// Builds the Connect JSON request for a manifest without sending it
    /// (exposed for testing the wire format).
    public func makeCreateBuildRequest(manifest: BuildProofManifest) throws -> HTTPRequestSpec {
        let manifestJSON = try manifest.jsonString()
        let payload: [String: Any] = [
            "tenantId": config.tenantId,
            "appId": config.appId,
            "buildHash": manifest.buildHash,
            "versionName": manifest.versionName,
            // proto3 JSON encodes int64 as a string.
            "versionCode": String(manifest.versionCode),
            "protectionProfileId": config.protectionProfileId.isEmpty ? manifest.protectionProfileId : config.protectionProfileId,
            "manifest": manifestJSON,
        ]
        let body = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        // Build the endpoint by string concatenation rather than
        // `appendingPathComponent`, which percent-encodes embedded slashes
        // differently across Foundation implementations (Apple vs. Linux
        // swift-corelibs). The Connect path is a single fixed RPC route.
        let base = config.baseURL.absoluteString
        let trimmedBase = base.hasSuffix("/") ? String(base.dropLast()) : base
        guard let url = URL(string: trimmedBase + Self.createBuildPath) else {
            throw RegistryError.transport("invalid registry URL: \(trimmedBase)\(Self.createBuildPath)")
        }
        return HTTPRequestSpec(
            url: url,
            method: "POST",
            headers: [
                "Content-Type": "application/json",
                "Authorization": "Bearer \(config.apiKey)",
                "Connect-Protocol-Version": "1",
            ],
            body: body
        )
    }

    /// Sends the manifest to the control plane and returns the server build id.
    public func createBuild(manifest: BuildProofManifest) throws -> String {
        let request = try makeCreateBuildRequest(manifest: manifest)
        let response: HTTPResponseSpec
        do {
            response = try transport.send(request)
        } catch {
            throw RegistryError.transport(String(describing: error))
        }
        guard (200..<300).contains(response.statusCode) else {
            throw RegistryError.httpStatus(response.statusCode, String(decoding: response.body, as: UTF8.self))
        }
        guard let obj = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
            throw RegistryError.decode("response was not a JSON object")
        }
        guard let build = obj["build"] as? [String: Any], let id = build["id"] as? String else {
            throw RegistryError.decode("response missing build.id")
        }
        return id
    }
}

/// Orchestrates registration with a guaranteed offline artifact fallback so a
/// build never fails just because the control plane is unreachable — the proof
/// is durably persisted and can be reconciled later.
public struct BuildProofRegistrar {
    private let transport: HTTPTransport
    private let fileSystem: FileManager

    public init(transport: HTTPTransport = URLSessionTransport(), fileSystem: FileManager = .default) {
        self.transport = transport
        self.fileSystem = fileSystem
    }

    /// Attempts registration; on any failure (or when `config` is nil/`offline`
    /// is set) writes the manifest to `offlineArtifact` and reports `.offline`.
    public func register(
        manifest: BuildProofManifest,
        config: RegistryConfig?,
        offlineArtifact: URL,
        forceOffline: Bool = false
    ) -> Result<RegistrationOutcome, Error> {
        if !forceOffline, let config = config {
            let client = RegistryClient(config: config, transport: transport)
            do {
                let id = try client.createBuild(manifest: manifest)
                return .success(.registered(buildId: id))
            } catch {
                // Fall through to the offline artifact so the build still produces
                // a durable, reconcilable proof.
                return writeOffline(manifest: manifest, to: offlineArtifact)
                    .map { _ in .offline(artifactPath: offlineArtifact.path) }
            }
        }
        return writeOffline(manifest: manifest, to: offlineArtifact)
            .map { _ in .offline(artifactPath: offlineArtifact.path) }
    }

    private func writeOffline(manifest: BuildProofManifest, to url: URL) -> Result<Void, Error> {
        do {
            try fileSystem.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try manifest.jsonData().write(to: url, options: .atomic)
            return .success(())
        } catch {
            return .failure(error)
        }
    }
}
