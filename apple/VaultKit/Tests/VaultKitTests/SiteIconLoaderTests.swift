import Compression
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

/// Answers from a table (default: one public address) and records every lookup.
final class StaticResolver: HostResolver, Sendable {
    let table: [String: [String]?]
    let fallback: [String]
    private let seen = Mutex<[String]>([])

    init(_ table: [String: [String]?] = [:], fallback: [String] = ["93.184.215.14"]) {
        self.table = table
        self.fallback = fallback
    }

    var lookups: [String] { seen.withLock { $0 } }

    func addresses(for host: String) async -> [ResolvedAddress]? {
        seen.withLock { $0.append(host) }
        let texts: [String]? = table.keys.contains(host) ? table[host] ?? nil : fallback
        return texts?.compactMap(ResolvedAddress.init)
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
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
        #expect(await loader.icon(for: "http://http-only.exemple.fr/login") == nil)
        #expect(await loader.icon(for: "not a url") == nil)
        #expect(await loader.icon(for: "https://") == nil)
        #expect(await loader.icon(for: "ftp://http-only.exemple.fr") == nil)
        #expect(StubProtocol.requests(host: "http-only.exemple.fr").isEmpty)
    }

    @Test func iconLoaderDisabledReturnsNil() async {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "disabled.exemple.fr") { _ in .init(body: Self.pngData()) }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { false })
        #expect(await loader.icon(for: "https://disabled.exemple.fr") == nil)
        #expect(StubProtocol.requests(host: "disabled.exemple.fr").isEmpty)
    }

    @Test func iconLoaderRejectsOversizedResponse() async throws {
        let (session, _) = Self.makeSession()
        let directory = Self.tempDirectory()
        let big = Self.pngData() + Data(count: 300 * 1024)
        StubProtocol.install(host: "big.exemple.fr") { _ in .init(body: big) }
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, resolver: StaticResolver(), enabled: { true })
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
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
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
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, resolver: StaticResolver(), enabled: { true })
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
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
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
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
        #expect(await loader.icon(for: "https://fake.exemple.fr") == nil)
        #expect(!StubProtocol.requests(host: "fake.exemple.fr").contains { $0.url?.scheme == "http" })
    }

    @Test func expiredFailureMarkerIsRetried() async throws {
        let (session, _) = Self.makeSession()
        let directory = Self.tempDirectory()
        StubProtocol.install(host: "retry.exemple.fr") { _ in .init(status: 404) }
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, resolver: StaticResolver(), enabled: { true })
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

    /// A small grayscale PNG whose rows are all zero: `side` x `side` pixels declared and really
    /// encoded (a decode bomb: a few dozen KiB that inflate to `side`² bytes).
    static func zeroPNG(side: Int) throws -> Data {
        func crc32(_ bytes: [UInt8]) -> UInt32 {
            var crc: UInt32 = 0xFFFF_FFFF
            for byte in bytes {
                crc ^= UInt32(byte)
                for _ in 0..<8 { crc = crc & 1 == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1 }
            }
            return ~crc
        }
        func be(_ v: UInt32) -> [UInt8] {
            [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
        }
        func chunk(_ type: String, _ body: [UInt8]) -> [UInt8] {
            let typed = Array(type.utf8) + body
            return be(UInt32(body.count)) + typed + be(crc32(typed))
        }
        // zlib stream: header, raw DEFLATE of the rows (filter byte 0 then zero pixels), Adler-32.
        var deflated = Data()
        let filter = try OutputFilter(.compress, using: .zlib) { if let d = $0 { deflated.append(d) } }
        let row = Data(count: side + 1)
        for _ in 0..<side { try filter.write(row) }
        try filter.finalize()
        let rawCount = UInt32((side + 1) * side % 65521)
        let idat = [0x78, 0x01] + Array(deflated) + be(rawCount << 16 | 1)
        let ihdr = be(UInt32(side)) + be(UInt32(side)) + [8, 0, 0, 0, 0]
        let signature: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        return Data(signature + chunk("IHDR", ihdr) + chunk("IDAT", idat) + chunk("IEND", []))
    }

    @Test func hugeDeclaredImageIsRefusedBeforeDecoding() async throws {
        let bomb = try Self.zeroPNG(side: 5000)
        #expect(bomb.count < SiteIconLoader.maxBytes)
        let size = try #require(SiteIconLoader.declaredPixelSize(bomb))
        #expect(size.width == 5000 && size.height == 5000)
        #expect(SiteIconLoader.normalizedPNG(bomb) == nil)
        #expect(SiteIconLoader.normalizedPNG(try Self.zeroPNG(side: 512)) != nil)
        #expect(SiteIconLoader.normalizedPNG(Self.pngData(side: 64)) != nil)

        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "bombe.exemple.fr") { _ in .init(body: bomb) }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
        #expect(await loader.icon(for: "https://bombe.exemple.fr") == nil)
    }

    @Test(arguments: [
        "https://192.168.1.1/admin", "https://10.0.0.1", "https://127.0.0.1:8443", "https://127.1",
        "https://0x7f.0x1", "https://[::1]/", "https://[fe80::1]", "https://localhost/",
        "https://imprimante.local", "https://nas", "https://routeur./", "https://app.localhost",
        "https://box.lan", "https://nas.home.arpa", "https://wiki.internal", "https://srv.localdomain",
        "https://routeur.home", "https://portail.intranet", "https://git.corp", "https://nas.private",
        "https://NAS.LAN.",
    ])
    func privateHostsAreNeverFetched(url: String) async {
        let (session, _) = Self.makeSession()
        let host = URLComponents(string: url)?.host ?? url
        StubProtocol.install(host: host) { _ in .init(body: Self.pngData()) }
        let resolver = StaticResolver()
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: url) == nil)
        #expect(StubProtocol.requests(host: host).isEmpty)
        // Refused by name: not even resolved.
        #expect(resolver.lookups.isEmpty)
    }

    /// A public name that resolves to a private address (or a mix) is refused before any request.
    @Test(arguments: [
        ["10.1.2.3"], ["192.168.1.20"], ["172.20.0.5"], ["127.0.0.1"], ["169.254.10.1"], ["100.100.1.1"],
        ["0.0.0.0"], ["224.0.0.251"], ["255.255.255.255"], ["::1"], ["::"], ["fe80::1"], ["fd12:3456::1"],
        ["fc00::7"], ["ff02::fb"], ["::ffff:192.168.1.1"], ["64:ff9b::a00:1"], ["93.184.215.14", "10.0.0.1"],
        ["2606:2800:21f:cb07:6820:80da:af6b:8b2c", "fd00::1"], [],
    ])
    func namesResolvingToPrivateAddressesAreNeverFetched(addresses: [String]) async {
        let (session, _) = Self.makeSession()
        let host = "rebind-\(UUID().uuidString.prefix(8).lowercased()).exemple.fr"
        StubProtocol.install(host: host) { _ in .init(body: Self.pngData()) }
        let resolver = StaticResolver([host: addresses])
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://\(host)/") == nil)
        #expect(resolver.lookups == [host])
        #expect(StubProtocol.requests(host: host).isEmpty)
        // Remembered as a failure: not resolved again right away.
        #expect(await loader.icon(for: "https://\(host)/") == nil)
        #expect(resolver.lookups == [host])
    }

    @Test func publicAddressesAreFetched() async throws {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "public.exemple.fr") { _ in .init(body: Self.pngData()) }
        let resolver = StaticResolver([
            "public.exemple.fr": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]
        ])
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://public.exemple.fr") != nil)
        #expect(!StubProtocol.requests(host: "public.exemple.fr").isEmpty)
    }

    /// No answer in time: no request, and no failure marker (the next display tries again).
    @Test func unresolvedNameIsNotFetchedNorRemembered() async {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "lent.exemple.fr") { _ in .init(body: Self.pngData()) }
        let resolver = StaticResolver(["lent.exemple.fr": nil])
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://lent.exemple.fr") == nil)
        #expect(await loader.icon(for: "https://lent.exemple.fr") == nil)
        #expect(resolver.lookups.count == 2)
        #expect(StubProtocol.requests(host: "lent.exemple.fr").isEmpty)
    }

    @Test func addressClassification() {
        for text in ["93.184.215.14", "1.1.1.1", "100.63.255.255", "100.128.0.1", "172.15.0.1", "172.32.0.1",
            "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "::ffff:93.184.215.14", "64:ff9b::5db8:d70e",
            "2002:5db8:d70e::1", "192.0.3.1", "198.51.101.1", "203.0.114.1", "100:0:0:1::1", "2001:1::1",
            "2001:db9::1"]
        {
            #expect(ResolvedAddress(text)?.isPublic == true, "\(text)")
        }
        for text in ["10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.169.254", "172.16.0.1",
            "172.31.255.255", "192.168.0.1", "0.1.2.3", "224.0.0.1", "239.255.255.250", "255.255.255.255",
            "::1", "::", "fe80::1", "febf::1", "fc00::1", "fdff::1", "ff02::1", "::ffff:10.0.0.1", "::7f00:1",
            "64:ff9b::7f00:1", "192.0.2.10", "198.51.100.7", "203.0.113.200", "2002:c0a8:101::1", "2002:7f00:1::",
            "2002:a00:1::5", "::ffff:0:5db8:d70e", "::ffff:0:a00:1", "64:ff9b:1::5db8:d70e", "2001:0:4136:e378::1",
            "100::1", "100::ffff:ffff:ffff:ffff", "2001:db8::1", "2001:db8:ffff::1"]
        {
            #expect(ResolvedAddress(text)?.isPublic == false, "\(text)")
        }
        #expect(ResolvedAddress("pas une adresse") == nil)
        #expect(ResolvedAddress(bytes: [1, 2, 3]) == nil)
    }

    /// The system resolver answers for a literal without the network, off the main thread.
    @Test func systemResolverParsesLiterals() async throws {
        let resolver = SystemHostResolver(timeout: .seconds(2))
        let v4 = try #require(await resolver.addresses(for: "127.0.0.1"))
        #expect(v4.contains(ResolvedAddress("127.0.0.1")!))
        #expect(v4.allSatisfy { !$0.isPublic })
    }

    @Test func publicHostNamesStayFetchable() {
        for host in [
            "exemple.fr", "www.exemple.fr", "atlas-42.exemple.fr", "a1.b2.fr", "exemple.fr.", "lan.exemple.fr",
            "corp.exemple.fr", "private.exemple.fr", "home.exemple.fr", "maison.homes", "atlas.corporate",
        ] {
            #expect(SiteIconLoader.isFetchableHost(host), "\(host)")
        }
        for host in [
            "192.168.0.10", "::1", "localhost", "nas", "imprimante.local", "", "a..fr", "box.lan",
            "nas.home.arpa", "home.arpa", "wiki.internal", "srv.localdomain", "routeur.home", "git.corp",
        ] {
            #expect(!SiteIconLoader.isFetchableHost(host), "\(host)")
        }
    }
}
