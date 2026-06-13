import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Minimal synchronous HTTP POST seam used by the Connect trust client.
///
/// Abstracted so the trust flow can be unit-tested with a deterministic fake
/// (no sockets, no server) while production uses `URLSessionTransport`.
public protocol HTTPTransport {
    /// POSTs `body` to `url` with `headers` and returns the status + body.
    func post(url: URL, headers: [String: String], body: Data) throws -> HTTPResponse
}

/// A transport response: HTTP status code and raw body bytes.
public struct HTTPResponse: Sendable {
    public let status: Int
    public let body: Data

    public init(status: Int, body: Data) {
        self.status = status
        self.body = body
    }
}

/// Production transport backed by `URLSession`.
///
/// The trust flow runs off the launch hot path, so a bounded synchronous call
/// (the host typically dispatches it to a background queue) keeps the public
/// API simple. A configurable timeout fails closed rather than hanging.
public final class URLSessionTransport: HTTPTransport {
    private let session: URLSession
    private let timeout: TimeInterval

    public init(session: URLSession = .shared, timeout: TimeInterval = 10) {
        self.session = session
        self.timeout = timeout
    }

    public func post(url: URL, headers: [String: String], body: Data) throws -> HTTPResponse {
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.httpBody = body
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        let semaphore = DispatchSemaphore(value: 0)
        let box = ResultBox()

        let task = session.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }
            if let error {
                box.set(.failure(TrustSessionError(message: "transport error: \(error.localizedDescription)")))
                return
            }
            guard let http = response as? HTTPURLResponse else {
                box.set(.failure(TrustSessionError(message: "non-HTTP response")))
                return
            }
            box.set(.success(HTTPResponse(status: http.statusCode, body: data ?? Data())))
        }
        task.resume()

        if semaphore.wait(timeout: .now() + timeout + 1) == .timedOut {
            task.cancel()
            throw TrustSessionError(message: "trust request timed out after \(timeout)s")
        }
        return try box.get()
    }
}

/// Thread-safe one-shot result holder bridging the `URLSession` completion
/// callback (which runs on a delegate queue) back to the waiting caller.
private final class ResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<HTTPResponse, Error> = .failure(
        TrustSessionError(message: "transport produced no response")
    )

    func set(_ value: Result<HTTPResponse, Error>) {
        lock.lock(); defer { lock.unlock() }
        result = value
    }

    func get() throws -> HTTPResponse {
        lock.lock(); defer { lock.unlock() }
        return try result.get()
    }
}
