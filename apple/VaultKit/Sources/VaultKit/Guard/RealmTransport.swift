import Foundation
import OnePassCore

/// The Guarded Kit transport (spec 2026-11-20, section 7): one HTTPS POST of the opaque request body
/// to the realm URL the core gives, the response body back. The core checks every response against
/// the realm keys pinned in the build, so this only moves bytes: no cookies, no cache, no
/// credentials, a short timeout. Any failure (offline, timeout, TLS, a status other than 200, a URL
/// that is not HTTPS) throws; the core then tries the next realm or reports `GuardUnavailable`.
///
/// Called synchronously on the core thread (never on the main actor), sometimes while the core
/// holds its session: it never calls back into the FFI.
public final class URLSessionRealmTransport: FfiRealmTransport, @unchecked Sendable {
    /// Per request: a realm that does not answer within this is skipped.
    public static let defaultTimeout: TimeInterval = 10
    /// Largest response body accepted (realm answers are a few hundred bytes).
    static let maxResponseBytes = 64 * 1024

    private let session: URLSession
    private let timeout: TimeInterval

    public init(timeout: TimeInterval = URLSessionRealmTransport.defaultTimeout) {
        self.timeout = timeout
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration)
    }

    deinit {
        session.invalidateAndCancel()
    }

    public func call(url: String, request: Data) throws -> Data {
        guard let target = URL(string: url), target.scheme?.lowercased() == "https", target.host != nil else {
            throw OnePassError.GuardRealm
        }
        var post = URLRequest(url: target, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: timeout)
        post.httpMethod = "POST"
        post.httpBody = request
        post.httpShouldHandleCookies = false
        post.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        post.setValue("application/octet-stream", forHTTPHeaderField: "Accept")

        let box = ResponseBox()
        let done = DispatchSemaphore(value: 0)
        let task = session.dataTask(with: post) { data, response, error in
            box.set(data: data, response: response, error: error)
            done.signal()
        }
        task.resume()
        // URLSession enforces the timeout; the extra second covers its callback.
        if done.wait(timeout: .now() + timeout + 1) == .timedOut {
            task.cancel()
            throw OnePassError.GuardRealm
        }
        let (data, response, error) = box.get()
        guard error == nil, let http = response as? HTTPURLResponse, http.statusCode == 200,
            let data, data.count <= Self.maxResponseBytes
        else { throw OnePassError.GuardRealm }
        return data
    }
}

/// The completion handler's result, handed from URLSession's queue to the waiting core thread.
private final class ResponseBox: @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    private var response: URLResponse?
    private var error: (any Error)?

    func set(data: Data?, response: URLResponse?, error: (any Error)?) {
        lock.lock()
        defer { lock.unlock() }
        self.data = data
        self.response = response
        self.error = error
    }

    func get() -> (Data?, URLResponse?, (any Error)?) {
        lock.lock()
        defer { lock.unlock() }
        return (data, response, error)
    }
}
