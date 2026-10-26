import CoreGraphics
import CryptoKit
import Foundation
import ImageIO
import Synchronization
import Testing
import UniformTypeIdentifiers

@testable import VaultKit

/// Serves canned responses per host and records every request. Handlers are keyed by
/// host so tests running in parallel never see each other's traffic.
final class StubProtocol: URLProtocol, @unchecked Sendable {
    struct Reply { var status = 200; var headers: [String: String] = [:]; var body = Data() }
    typealias Handler = @Sendable (URLRequest) -> Reply

    private static let state = Mutex<(handlers: [String: Handler], seen: [String: [URLRequest]])>(([:], [:]))

    static func install(host: String, _ handler: @escaping Handler) {
        state.withLock { $0.handlers[host] = handler; $0.seen[host] = [] }
    }
    static func requests(host: String) -> [URLRequest] { state.withLock { $0.seen[host] ?? [] } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        let host = request.url?.host ?? ""
        let handler = Self.state.withLock { state -> Handler? in
            state.seen[host, default: []].append(request)
            return state.handlers[host]
        }
        guard let handler, let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotFindHost))
            return
        }
        let reply = handler(request)
        let response = HTTPURLResponse(
            url: url, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: reply.headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: reply.body)
        client?.urlProtocolDidFinishLoading(self)
    }
}

@Suite("SiteIconLoader")
struct SiteIconLoaderTests {
    static func makeSession() -> (URLSession, HTTPCookieStorage) {
        let configuration = URLSession.ephemeralNoCookiesConfiguration
        configuration.protocolClasses = [StubProtocol.self]
        let storage = HTTPCookieStorage.sharedCookieStorage(forGroupContainerIdentifier: "test-\(UUID())")
        configuration.httpCookieStorage = storage
        return (URLSession(configuration: configuration), storage)
    }

    static func tempDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("siteicons-\(UUID().uuidString)")
    }

    static func pngData(side: Int = 32) -> Data {
        let context = CGContext(
            data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        context.setFillColor(red: 0.2, green: 0.5, blue: 0.9, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: side, height: side))
        let data = NSMutableData()
        let destination = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(destination, context.makeImage()!, nil)
        CGImageDestinationFinalize(destination)
        return data as Data
    }

    static func cacheName(_ host: String) -> String {
        SHA256.hash(data: Data(host.lowercased().utf8)).map { String(format: "%02x", $0) }.joined() + ".png"
    }

    @Test func iconLoaderRefusesHTTP() async {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "http-only.exemple.fr") { _ in .init(body: Self.pngData()) }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, enabled: { true })
        #expect(await loader.icon(for: "http://http-only.exemple.fr/login") == nil)
        #expect(await loader.icon(for: "not a url") == nil)
        #expect(await loader.icon(for: "https://") == nil)
        #expect(await loader.icon(for: "ftp://http-only.exemple.fr") == nil)
        #expect(StubProtocol.requests(host: "http-only.exemple.fr").isEmpty)
    }

    @Test func iconLoaderDisabledReturnsNil() async {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "disabled.exemple.fr") { _ in .init(body: Self.pngData()) }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, enabled: { false })
        #expect(await loader.icon(for: "https://disabled.exemple.fr") == nil)
        #expect(StubProtocol.requests(host: "disabled.exemple.fr").isEmpty)
    }

    @Test func iconLoaderRejectsOversizedResponse() async throws {
        let (session, _) = Self.makeSession()
        let directory = Self.tempDirectory()
        let big = Self.pngData() + Data(count: 300 * 1024)
        StubProtocol.install(host: "big.exemple.fr") { _ in .init(body: big) }
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, enabled: { true })
        #expect(await loader.icon(for: "https://big.exemple.fr") == nil)
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent(Self.cacheName("big.exemple.fr")).path))
        // The failure is remembered: no further traffic.
        let count = StubProtocol.requests(host: "big.exemple.fr").count
        #expect(count > 0)
        #expect(await loader.icon(for: "https://big.exemple.fr") == nil)
        #expect(StubProtocol.requests(host: "big.exemple.fr").count == count)
    }

    @Test func iconLoaderSendsNoCookies() async throws {
        let (session, storage) = Self.makeSession()
        let configuration = session.configuration
        #expect(configuration.httpShouldSetCookies == false)
        #expect(configuration.httpCookieAcceptPolicy == .never)
        let seeded = try #require(HTTPCookie(properties: [
            .domain: "cookies.exemple.fr", .path: "/", .name: "sid", .value: "fictif",
        ]))
        storage.setCookie(seeded)
        StubProtocol.install(host: "cookies.exemple.fr") { _ in
            .init(headers: ["Set-Cookie": "tracker=1; Path=/"], body: Self.pngData())
        }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, enabled: { true })
        let data = await loader.icon(for: "https://cookies.exemple.fr/compte")
        #expect(data != nil)
        let requests = StubProtocol.requests(host: "cookies.exemple.fr")
        #expect(!requests.isEmpty)
        for request in requests {
            #expect(request.value(forHTTPHeaderField: "Cookie") == nil)
        }
        #expect(storage.cookies(for: URL(string: "https://cookies.exemple.fr")!)?.contains { $0.name == "tracker" } != true)
    }

    @Test func iconLoaderFetchesAndCachesAppleTouchIcon() async throws {
        let (session, _) = Self.makeSession()
        let directory = Self.tempDirectory()
        StubProtocol.install(host: "touch.exemple.fr") { request in
            request.url?.path == "/apple-touch-icon.png" ? .init(body: Self.pngData()) : .init(status: 404)
        }
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, enabled: { true })
        let data = try #require(await loader.icon(for: "https://Touch.Exemple.fr/a/b?x=1"))
        #expect(CGImageSourceCreateWithData(data as CFData, nil) != nil)
        let file = directory.appendingPathComponent(Self.cacheName("touch.exemple.fr"))
        #expect(FileManager.default.fileExists(atPath: file.path))
        let count = StubProtocol.requests(host: "touch.exemple.fr").count
        #expect(await loader.icon(for: "https://touch.exemple.fr") == data)
        #expect(StubProtocol.requests(host: "touch.exemple.fr").count == count)
    }

    @Test func iconLoaderFallsBackToFaviconThenPageLink() async throws {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "favicon.exemple.fr") { request in
            request.url?.path == "/favicon.ico" ? .init(body: Self.pngData()) : .init(status: 404)
        }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, enabled: { true })
        #expect(await loader.icon(for: "https://favicon.exemple.fr") != nil)

        let html = #"<html><head><link rel="stylesheet" href="/s.css"><link rel="shortcut icon" href="/assets/i.png"></head></html>"#
        StubProtocol.install(host: "link.exemple.fr") { request in
            switch request.url?.path {
            case "/assets/i.png": .init(body: Self.pngData())
            case "", "/": .init(headers: ["Content-Type": "text/html"], body: Data(html.utf8))
            default: .init(status: 404)
            }
        }
        #expect(await loader.icon(for: "https://link.exemple.fr/login") != nil)
    }

    @Test func iconLoaderRejectsNonImageAndHTTPLinks() async throws {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "fake.exemple.fr") { request in
            switch request.url?.path {
            case "/apple-touch-icon.png", "/favicon.ico": .init(body: Data("<html>pas une image</html>".utf8))
            case "", "/": .init(body: Data(#"<link rel="icon" href="http://fake.exemple.fr/i.png">"#.utf8))
            default: .init(body: Self.pngData())
            }
        }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, enabled: { true })
        #expect(await loader.icon(for: "https://fake.exemple.fr") == nil)
        #expect(!StubProtocol.requests(host: "fake.exemple.fr").contains { $0.url?.scheme == "http" })
    }

    @Test func expiredFailureMarkerIsRetried() async throws {
        let (session, _) = Self.makeSession()
        let directory = Self.tempDirectory()
        StubProtocol.install(host: "retry.exemple.fr") { _ in .init(status: 404) }
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, enabled: { true })
        #expect(await loader.icon(for: "https://retry.exemple.fr") == nil)
        let first = StubProtocol.requests(host: "retry.exemple.fr").count
        #expect(await loader.icon(for: "https://retry.exemple.fr") == nil)
        #expect(StubProtocol.requests(host: "retry.exemple.fr").count == first)

        let markers = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "miss" }
        let marker = try #require(markers.first)
        try FileManager.default.setAttributes(
            [.modificationDate: Date().addingTimeInterval(-8 * 24 * 3600)], ofItemAtPath: marker.path)
        StubProtocol.install(host: "retry.exemple.fr") { _ in .init(body: Self.pngData()) }
        #expect(await loader.icon(for: "https://retry.exemple.fr") != nil)
    }
}
