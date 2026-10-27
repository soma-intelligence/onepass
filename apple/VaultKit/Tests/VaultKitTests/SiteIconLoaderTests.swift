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
        // A 3xx with a Location goes through the session's redirect delegate like a real one.
        if (300..<400).contains(reply.status), let location = reply.headers["Location"],
            let target = URL(string: location, relativeTo: url)?.absoluteURL {
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
        }
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

    static func pngData(side: Int = 32, height: Int? = nil) -> Data {
        let context = CGContext(
            data: nil, width: side, height: height ?? side, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        context.setFillColor(red: 0.2, green: 0.5, blue: 0.9, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: side, height: height ?? side))
        let data = NSMutableData()
        let destination = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(destination, context.makeImage()!, nil)
        CGImageDestinationFinalize(destination)
        return data as Data
    }

    static func cacheName(_ host: String) -> String {
        SHA256.hash(data: Data(host.lowercased().utf8)).map { String(format: "%02x", $0) }.joined() + ".v2.png"
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
            case "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png", "/favicon.ico":
                .init(body: Data("<html>pas une image</html>".utf8))
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

    // MARK: Quality

    /// Side of a stored PNG (they are square).
    static func side(_ png: Data?) -> Int? {
        png.flatMap(SiteIconLoader.declaredPixelSize).map { max($0.width, $0.height) }
    }

    /// Alpha of one pixel, row 0 at the top.
    static func alpha(_ png: Data, x: Int, y: Int) -> UInt8? {
        guard let source = CGImageSourceCreateWithData(png as CFData, nil),
            let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
        else { return nil }
        var pixels = [UInt8](repeating: 0, count: image.width * image.height * 4)
        let drawn = pixels.withUnsafeMutableBytes { buffer -> Bool in
            guard let context = CGContext(
                data: buffer.baseAddress, width: image.width, height: image.height, bitsPerComponent: 8,
                bytesPerRow: image.width * 4, space: CGColorSpaceCreateDeviceRGB(),
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
            else { return false }
            context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
            return true
        }
        guard drawn else { return nil }
        return pixels[(y * image.width + x) * 4 + 3]
    }

    /// An ICO file holding one PNG per side.
    static func icoData(sides: [Int]) -> Data {
        func le16(_ v: Int) -> [UInt8] { [UInt8(v & 0xFF), UInt8(v >> 8 & 0xFF)] }
        func le32(_ v: Int) -> [UInt8] { le16(v & 0xFFFF) + le16(v >> 16) }
        let images = sides.map { pngData(side: $0) }
        var header: [UInt8] = [0, 0, 1, 0] + le16(sides.count)
        var offset = 6 + 16 * sides.count
        for (side, image) in zip(sides, images) {
            let byte = UInt8(side >= 256 ? 0 : side)
            header += [byte, byte, 0, 0] + le16(1) + le16(32) + le32(image.count) + le32(offset)
            offset += image.count
        }
        return images.reduce(Data(header), +)
    }

    @Test func pageLinksAreRankedBySize() throws {
        let html = """
            <link rel="icon" href="/i16.png" sizes="16x16">
            <link rel=icon href=/i96.png sizes="32x32 96x96">
            <link rel="shortcut icon" href="/favicon.ico">
            <link rel="apple-touch-icon" href="/t.png">
            <link rel="apple-touch-icon-precomposed" sizes="152x152" href="/t152.png">
            <link rel="mask-icon" href="/mask.svg" color="#000">
            <link rel="icon" type="image/svg+xml" href="/i.svg" sizes="any">
            <link rel="icon" href="https://cdn.ailleurs.fr/i512.png" sizes="512x512">
            <link rel="icon" href="http://rang.exemple.fr/i256.png" sizes="256x256">
            <link rel="manifest" href="/site.webmanifest">
            <link rel="stylesheet" href="/s.css">
            """
        let base = URL(string: "https://rang.exemple.fr/")!
        let page = SiteIconLoader.pageLinks(in: Data(html.utf8), base: base, host: "rang.exemple.fr")
        #expect(page.manifest?.absoluteString == "https://rang.exemple.fr/site.webmanifest")
        let order = SiteIconLoader.ranked(page.icons + SiteIconLoader.wellKnownCandidates(host: "rang.exemple.fr"))
            .map(\.url.path)
        let expected = [
            "/i.svg", "/t.png", "/t152.png", "/i96.png", "/i16.png", "/favicon.ico",
            "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png", "/mask.svg",
        ]
        // Where SVG cannot be drawn it is not even fetched.
        #expect(order == (SiteIconLoader.rendersSVG ? expected : expected.filter { !$0.hasSuffix(".svg") }))
    }

    @Test func manifestIconsSkipMonochromeAndOtherHosts() {
        let json = """
            {"icons": [
              {"src": "/m/192.png", "sizes": "192x192", "type": "image/png"},
              {"src": "512.png", "sizes": "512x512", "purpose": "any maskable"},
              {"src": "/m/mono.png", "sizes": "1024x1024", "purpose": "monochrome"},
              {"src": "https://cdn.ailleurs.fr/1024.png", "sizes": "1024x1024"},
              {"sizes": "64x64"}
            ]}
            """
        let base = URL(string: "https://manifeste.exemple.fr/m/site.webmanifest")!
        let icons = SiteIconLoader.manifestIcons(in: Data(json.utf8), base: base, host: "manifeste.exemple.fr")
        #expect(icons.map(\.url.path) == ["/m/192.png", "/m/512.png"])
        #expect(icons.map(\.declared) == [192, 512])
        #expect(SiteIconLoader.manifestIcons(in: Data("pas du json".utf8), base: base, host: "manifeste.exemple.fr").isEmpty)
    }

    @Test func largestDeclaredIconIsFetchedFirst() async throws {
        let (session, _) = Self.makeSession()
        let html = #"<link rel="icon" href="/i16.png" sizes="16x16"><link rel="apple-touch-icon" sizes="180x180" href="/t180.png">"#
        StubProtocol.install(host: "grand.exemple.fr") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(html.utf8))
            case "/i16.png": .init(body: Self.pngData(side: 16))
            case "/t180.png": .init(body: Self.pngData(side: 180))
            default: .init(status: 404)
            }
        }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
        let png = try #require(await loader.icon(for: "https://grand.exemple.fr/login"))
        #expect(Self.side(png) == 256)
        let paths = StubProtocol.requests(host: "grand.exemple.fr").compactMap(\.url?.path)
        #expect(paths.contains("/t180.png"))
        // A good icon ends the search.
        #expect(!paths.contains("/i16.png"))
        #expect(!paths.contains("/favicon.ico"))
    }

    @Test func manifestIconIsUsed() async throws {
        let (session, _) = Self.makeSession()
        let html = #"<link rel="icon" href="/favicon.ico"><link rel="manifest" href="/app.webmanifest">"#
        let manifest = #"{"icons": [{"src": "/icon-192.png", "sizes": "192x192"}, {"src": "/icon-512.png", "sizes": "512x512"}]}"#
        StubProtocol.install(host: "pwa.exemple.fr") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(html.utf8))
            case "/app.webmanifest": .init(body: Data(manifest.utf8))
            case "/icon-192.png": .init(body: Self.pngData(side: 192))
            case "/icon-512.png": .init(body: Self.pngData(side: 512))
            case "/favicon.ico": .init(body: Self.pngData(side: 16))
            default: .init(status: 404)
            }
        }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
        let png = try #require(await loader.icon(for: "https://pwa.exemple.fr"))
        #expect(Self.side(png) == 256)
        let paths = StubProtocol.requests(host: "pwa.exemple.fr").compactMap(\.url?.path)
        #expect(paths.contains("/icon-512.png"))
        #expect(!paths.contains("/icon-192.png"))
        #expect(!paths.contains("/favicon.ico"))
    }

    @Test func icoUsesItsLargestImage() throws {
        let ico = Self.icoData(sides: [16, 200, 32])
        let decoded = try #require(SiteIconLoader.decodeIcon(ico))
        #expect(decoded.sourcePixels == 200)
        #expect(Self.side(decoded.png) == 256)

        let small = try #require(SiteIconLoader.decodeIcon(Self.icoData(sides: [16, 48])))
        #expect(small.sourcePixels == 48)
        // Never more than twice the source.
        #expect(Self.side(small.png) == 96)
    }

    @Test func tinyIconIsOnlyALastResort() async throws {
        let (session, _) = Self.makeSession()
        // The page's icon is tiny: the next candidates are tried and the larger one wins.
        StubProtocol.install(host: "minuscule.exemple.fr") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(#"<link rel="icon" href="/f.png">"#.utf8))
            case "/f.png": .init(body: Self.pngData(side: 16))
            case "/favicon.ico": .init(body: Self.icoData(sides: [16, 32]))
            default: .init(status: 404)
            }
        }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
        let png = try #require(await loader.icon(for: "https://minuscule.exemple.fr"))
        #expect(Self.side(png) == 64)
        let paths = StubProtocol.requests(host: "minuscule.exemple.fr").compactMap(\.url?.path)
        #expect(paths.contains("/apple-touch-icon.png"))
        #expect(paths.contains("/favicon.ico"))

        // Nothing better anywhere: the tiny one is kept.
        StubProtocol.install(host: "seul.exemple.fr") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(#"<link rel="icon" href="/f.png">"#.utf8))
            case "/f.png": .init(body: Self.pngData(side: 16))
            default: .init(status: 404)
            }
        }
        #expect(Self.side(await loader.icon(for: "https://seul.exemple.fr")) == 32)
    }

    @Test func iconsAreSquaredWithTransparentPadding() throws {
        let wide = try #require(SiteIconLoader.decodeIcon(Self.pngData(side: 300, height: 150)))
        #expect(wide.sourcePixels == 300)
        #expect(SiteIconLoader.declaredPixelSize(wide.png)?.width == 256)
        #expect(SiteIconLoader.declaredPixelSize(wide.png)?.height == 256)
        #expect(Self.alpha(wide.png, x: 128, y: 2) == 0)
        #expect(Self.alpha(wide.png, x: 128, y: 128) == 255)
        // Never upscaled past twice the source.
        #expect(Self.side(SiteIconLoader.normalizedPNG(Self.pngData(side: 40))) == 80)
        #expect(Self.side(SiteIconLoader.normalizedPNG(Self.pngData(side: 128))) == 256)
        #expect(Self.side(SiteIconLoader.normalizedPNG(Self.pngData(side: 1024))) == 256)
    }

    @Test func svgSafety() {
        let ok = ##"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10"><defs><linearGradient id="g"/></defs><rect width="10" height="10" fill="url(#g)"/><use href="#g"/><use xlink:href='#g'/></svg>"##
        #expect(SiteIconLoader.isSafeSVG(Data(ok.utf8)))
        for bad in [
            #"<!DOCTYPE svg [<!ENTITY a "aaaa">]><svg>&a;</svg>"#,
            #"<svg><script>alert(1)</script></svg>"#,
            #"<svg><image href="https://traceur.fr/p.png"/></svg>"#,
            #"<svg><use href="https://traceur.fr/s.svg#a"/></svg>"#,
            #"<svg><use xlink:href=" https://traceur.fr/s.svg#a"/></svg>"#,
            #"<svg><use href=//traceur.fr/s.svg#a /></svg>"#,
            #"<svg><rect style="fill: url(https://traceur.fr/x)"/></svg>"#,
            #"<svg><rect style="fill: url( 'https://traceur.fr/x')"/></svg>"#,
            #"<svg><style>@import "https://traceur.fr/x.css";</style></svg>"#,
            #"<svg><foreignObject><div/></foreignObject></svg>"#,
            #"pas du svg"#,
            #"%PDF-1.4 <svg>"#,
        ] {
            #expect(!SiteIconLoader.isSafeSVG(Data(bad.utf8)), "\(bad)")
        }
    }

    #if os(macOS)
    @Test func svgIconIsDrawnAtFullSize() async throws {
        let (session, _) = Self.makeSession()
        let svg = ##"<svg xmlns="http://www.w3.org/2000/svg" width="20" height="10" viewBox="0 0 20 10"><rect width="20" height="10" fill="#3366cc"/></svg>"##
        StubProtocol.install(host: "vecteur.exemple.fr") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(#"<link rel="icon" type="image/svg+xml" href="/i.svg"><link rel="icon" href="/f.png">"#.utf8))
            case "/i.svg": .init(headers: ["Content-Type": "image/svg+xml"], body: Data(svg.utf8))
            case "/f.png": .init(body: Self.pngData(side: 16))
            default: .init(status: 404)
            }
        }
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: StaticResolver(), enabled: { true })
        let png = try #require(await loader.icon(for: "https://vecteur.exemple.fr"))
        #expect(Self.side(png) == 256)
        #expect(Self.alpha(png, x: 128, y: 128) == 255)
        #expect(Self.alpha(png, x: 128, y: 2) == 0)
        #expect(!StubProtocol.requests(host: "vecteur.exemple.fr").contains { $0.url?.path == "/f.png" })

        // An SVG that would fetch something is never drawn: the next candidate is used.
        let tracking = #"<svg xmlns="http://www.w3.org/2000/svg"><image href="https://traceur.fr/p.png" width="10" height="10"/></svg>"#
        StubProtocol.install(host: "piege.exemple.fr") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(#"<link rel="icon" href="/i.svg"><link rel="icon" href="/f.png">"#.utf8))
            case "/i.svg": .init(body: Data(tracking.utf8))
            case "/f.png": .init(body: Self.pngData(side: 16))
            default: .init(status: 404)
            }
        }
        #expect(Self.side(await loader.icon(for: "https://piege.exemple.fr")) == 32)
    }
    #endif

    /// Icons of the 128 px cache are not reused: fetched again, and the old file goes.
    @Test func previousCacheVersionIsRefetched() async throws {
        let (session, _) = Self.makeSession()
        let directory = Self.tempDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let hash = SHA256.hash(data: Data("ancien.exemple.fr".utf8)).map { String(format: "%02x", $0) }.joined()
        let legacy = directory.appendingPathComponent(hash + ".png")
        try Self.pngData(side: 128).write(to: legacy)
        StubProtocol.install(host: "ancien.exemple.fr") { request in
            request.url?.path == "/apple-touch-icon.png" ? .init(body: Self.pngData(side: 180)) : .init(status: 404)
        }
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, resolver: StaticResolver(), enabled: { true })
        #expect(Self.side(await loader.icon(for: "https://ancien.exemple.fr")) == 256)
        #expect(!StubProtocol.requests(host: "ancien.exemple.fr").isEmpty)
        #expect(!FileManager.default.fileExists(atPath: legacy.path))
        #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent(Self.cacheName("ancien.exemple.fr")).path))
    }

    // MARK: Parent domain and redirects

    @Test func registrableDomains() {
        let expected: [String: String?] = [
            "dashboard.stripe.com": "stripe.com", "stripe.com": "stripe.com", "www.notion.so": "notion.so",
            "a.b.exemple.co.uk": "exemple.co.uk", "exemple.co.uk": "exemple.co.uk", "www.impots.gouv.fr": "impots.gouv.fr",
            "shop.exemple.com.au": "exemple.com.au", "camille.github.io": "camille.github.io", "Exemple.FR.": "exemple.fr",
            "co.uk": nil, "gouv.fr": nil, "github.io": nil, "com": nil, "a..fr": nil, "": nil,
        ]
        for (host, domain) in expected {
            #expect(SiteIconLoader.registrableDomain(of: host) == domain, "\(host)")
        }
        #expect(SiteIconLoader.siteHosts(for: "dashboard.stripe.com") == ["dashboard.stripe.com", "stripe.com", "www.stripe.com"])
        #expect(SiteIconLoader.siteHosts(for: "www.notion.so") == ["www.notion.so", "notion.so"])
        #expect(SiteIconLoader.siteHosts(for: "notion.so") == ["notion.so", "www.notion.so"])
        #expect(SiteIconLoader.siteHosts(for: "exemple.co.uk") == ["exemple.co.uk", "www.exemple.co.uk"])
        // Never a bare public suffix.
        #expect(SiteIconLoader.siteHosts(for: "co.uk") == ["co.uk"])
        #expect(SiteIconLoader.sameSite("notion.so", "www.notion.so"))
        #expect(!SiteIconLoader.sameSite("a.github.io", "b.github.io"))
        #expect(!SiteIconLoader.sameSite("exemple.co.uk", "autre.co.uk"))
    }

    /// The item's host has nothing: its registrable domain is asked, and the icon is cached under
    /// the item's host (the next load makes no request).
    @Test func parentDomainIsTriedWhenTheHostHasNoIcon() async throws {
        let (session, _) = Self.makeSession()
        let directory = Self.tempDirectory()
        StubProtocol.install(host: "tableau.parent-icone.fr") { _ in .init(status: 404) }
        StubProtocol.install(host: "parent-icone.fr") { request in
            request.url?.path == "/apple-touch-icon.png" ? .init(body: Self.pngData(side: 180)) : .init(status: 404)
        }
        StubProtocol.install(host: "www.parent-icone.fr") { _ in .init(body: Self.pngData(side: 180)) }
        let resolver = StaticResolver()
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, resolver: resolver, enabled: { true })
        let png = try #require(await loader.icon(for: "https://tableau.parent-icone.fr/login"))
        #expect(Self.side(png) == 256)
        #expect(!StubProtocol.requests(host: "tableau.parent-icone.fr").isEmpty)
        #expect(!StubProtocol.requests(host: "parent-icone.fr").isEmpty)
        // Found on the parent: `www.` is not asked.
        #expect(StubProtocol.requests(host: "www.parent-icone.fr").isEmpty)
        #expect(resolver.lookups == ["tableau.parent-icone.fr", "parent-icone.fr"])
        #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent(Self.cacheName("tableau.parent-icone.fr")).path))

        let child = StubProtocol.requests(host: "tableau.parent-icone.fr").count
        let parent = StubProtocol.requests(host: "parent-icone.fr").count
        #expect(await loader.icon(for: "https://tableau.parent-icone.fr") == png)
        #expect(StubProtocol.requests(host: "tableau.parent-icone.fr").count == child)
        #expect(StubProtocol.requests(host: "parent-icone.fr").count == parent)
    }

    /// `notion.so` with nothing on it: `www.notion.so` is asked; another subdomain then reuses the
    /// parent's cached icon without asking anything of `www.` again.
    @Test func wwwIsTriedAfterTheBareDomain() async throws {
        let (session, _) = Self.makeSession()
        let directory = Self.tempDirectory()
        StubProtocol.install(host: "nu-icone.fr") { _ in .init(status: 404) }
        StubProtocol.install(host: "www.nu-icone.fr") { request in
            request.url?.path == "/apple-touch-icon.png" ? .init(body: Self.pngData(side: 180)) : .init(status: 404)
        }
        StubProtocol.install(host: "compte.nu-icone.fr") { _ in .init(status: 404) }
        let loader = SiteIconLoader(cacheDirectory: directory, session: session, resolver: StaticResolver(), enabled: { true })
        #expect(await loader.icon(for: "https://nu-icone.fr") != nil)
        #expect(!StubProtocol.requests(host: "www.nu-icone.fr").isEmpty)
        #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent(Self.cacheName("nu-icone.fr")).path))

        let www = StubProtocol.requests(host: "www.nu-icone.fr").count
        let bare = StubProtocol.requests(host: "nu-icone.fr").count
        #expect(await loader.icon(for: "https://compte.nu-icone.fr") != nil)
        #expect(StubProtocol.requests(host: "www.nu-icone.fr").count == www)
        #expect(StubProtocol.requests(host: "nu-icone.fr").count == bare)
    }

    /// Every host misses: one failure marker for the item's host, nothing asked again for a week.
    @Test func everyHostMissingIsRemembered() async throws {
        let (session, _) = Self.makeSession()
        for host in ["app.vide-icone.fr", "vide-icone.fr", "www.vide-icone.fr"] {
            StubProtocol.install(host: host) { _ in .init(status: 404) }
        }
        let resolver = StaticResolver()
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://app.vide-icone.fr") == nil)
        #expect(resolver.lookups == ["app.vide-icone.fr", "vide-icone.fr", "www.vide-icone.fr"])
        #expect(await loader.icon(for: "https://app.vide-icone.fr") == nil)
        #expect(resolver.lookups.count == 3)
        // The parent's own miss is remembered too: another subdomain does not ask it again.
        let parent = StubProtocol.requests(host: "vide-icone.fr").count
        #expect(await loader.icon(for: "https://autre.vide-icone.fr") == nil)
        #expect(StubProtocol.requests(host: "vide-icone.fr").count == parent)
    }

    /// A parent name resolving to a private address is never asked; the next one still is.
    @Test func privateParentIsSkipped() async throws {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "app.prive-icone.fr") { _ in .init(status: 404) }
        StubProtocol.install(host: "prive-icone.fr") { _ in .init(body: Self.pngData(side: 180)) }
        StubProtocol.install(host: "www.prive-icone.fr") { request in
            request.url?.path == "/apple-touch-icon.png" ? .init(body: Self.pngData(side: 180)) : .init(status: 404)
        }
        let resolver = StaticResolver(["prive-icone.fr": ["10.0.0.7"]])
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://app.prive-icone.fr") != nil)
        #expect(StubProtocol.requests(host: "prive-icone.fr").isEmpty)
        #expect(!StubProtocol.requests(host: "www.prive-icone.fr").isEmpty)
    }

    /// The item's own name resolving to a private address stops there: no parent is asked.
    @Test func privateHostAsksNoParent() async {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "garde-icone.fr") { _ in .init(body: Self.pngData(side: 180)) }
        let resolver = StaticResolver(["nas.garde-icone.fr": ["192.168.1.4"]])
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://nas.garde-icone.fr") == nil)
        #expect(resolver.lookups == ["nas.garde-icone.fr"])
        #expect(StubProtocol.requests(host: "garde-icone.fr").isEmpty)
    }

    /// `redir-icone.fr` sends its home page to `www.redir-icone.fr`: followed once, and the search
    /// goes on there (the page's icon, no well known path asked of the first host).
    @Test func sameSiteRedirectIsFollowedOnce() async throws {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "redir-icone.fr") { request in
            request.url?.path == "/" || request.url?.path == ""
                ? .init(status: 301, headers: ["Location": "https://www.redir-icone.fr/"]) : .init(status: 404)
        }
        StubProtocol.install(host: "www.redir-icone.fr") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(#"<link rel="icon" href="/marque.png" sizes="192x192">"#.utf8))
            case "/marque.png": .init(body: Self.pngData(side: 192))
            default: .init(status: 404)
            }
        }
        let resolver = StaticResolver()
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://redir-icone.fr") != nil)
        #expect(StubProtocol.requests(host: "www.redir-icone.fr").contains { $0.url?.path == "/marque.png" })
        #expect(!StubProtocol.requests(host: "redir-icone.fr").contains { $0.url?.path == "/apple-touch-icon.png" })
        // The new host was checked before the hop.
        #expect(resolver.lookups == ["redir-icone.fr", "www.redir-icone.fr"])
    }

    /// Redirects off the site, to HTTP, to a private address or a second hop are refused.
    @Test func otherRedirectsAreRefused() async throws {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "autre-site-icone.fr") { _ in .init(body: Self.pngData(side: 180)) }
        StubProtocol.install(host: "interne.fuite-icone.fr") { _ in .init(body: Self.pngData(side: 180)) }
        StubProtocol.install(host: "cdn.fuite-icone.fr") { _ in .init(body: Self.pngData(side: 180)) }
        let targets = [
            "https://autre-site-icone.fr/i.png", "http://img.fuite-icone.fr/i.png",
            "https://interne.fuite-icone.fr/i.png", "https://www.fuite-icone.fr/hop2.png",
        ]
        StubProtocol.install(host: "www.fuite-icone.fr") { request in
            // A second hop, to yet another host of the site.
            request.url?.path == "/hop2.png"
                ? .init(status: 302, headers: ["Location": "https://cdn.fuite-icone.fr/i.png"]) : .init(status: 404)
        }
        StubProtocol.install(host: "fuite-icone.fr") { request in
            switch request.url?.path {
            case "/apple-touch-icon.png": .init(status: 302, headers: ["Location": targets[0]])
            case "/apple-touch-icon-precomposed.png": .init(status: 302, headers: ["Location": targets[1]])
            case "/favicon.ico": .init(status: 302, headers: ["Location": targets[2]])
            case "", "/": .init(body: Data(#"<link rel="icon" href="/hop.png" sizes="192x192">"#.utf8))
            case "/hop.png": .init(status: 302, headers: ["Location": targets[3]])
            default: .init(status: 404)
            }
        }
        let resolver = StaticResolver(["interne.fuite-icone.fr": ["10.0.0.9"]])
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://fuite-icone.fr/") == nil)
        #expect(StubProtocol.requests(host: "autre-site-icone.fr").isEmpty)
        #expect(StubProtocol.requests(host: "img.fuite-icone.fr").isEmpty)
        #expect(StubProtocol.requests(host: "interne.fuite-icone.fr").isEmpty)
        #expect(StubProtocol.requests(host: "cdn.fuite-icone.fr").isEmpty)
    }

    @Test func sameNameOtherSuffix() {
        #expect(SiteIconLoader.sameNameOtherSuffix("www.notion.so", "www.notion.com"))
        #expect(SiteIconLoader.sameNameOtherSuffix("exemple.fr", "exemple.com"))
        #expect(SiteIconLoader.sameNameOtherSuffix("exemple.fr", "exemple.co.uk"))
        #expect(!SiteIconLoader.sameNameOtherSuffix("exemple.fr", "www.exemple.fr"))
        #expect(!SiteIconLoader.sameNameOtherSuffix("exemple.fr", "autre.com"))
        #expect(!SiteIconLoader.sameNameOtherSuffix("exemple.fr", "com"))
    }

    /// `www.marque-icone.fr` sends its home page to `www.marque-icone.com`: the same name under
    /// another suffix, followed once, and the search goes on there.
    @Test func homePageMayHopToTheSameNameUnderAnotherSuffix() async throws {
        let (session, _) = Self.makeSession()
        StubProtocol.install(host: "www.marque-icone.fr") { request in
            request.url?.path == "/" || request.url?.path == ""
                ? .init(status: 301, headers: ["Location": "https://www.marque-icone.com/"]) : .init(status: 404)
        }
        StubProtocol.install(host: "www.marque-icone.com") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(#"<link rel="apple-touch-icon" href="/logo-ios.png">"#.utf8))
            case "/logo-ios.png": .init(body: Self.pngData(side: 180))
            default: .init(status: 404)
            }
        }
        let resolver = StaticResolver()
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://www.marque-icone.fr/compte") != nil)
        #expect(StubProtocol.requests(host: "www.marque-icone.com").contains { $0.url?.path == "/logo-ios.png" })
        #expect(resolver.lookups == ["www.marque-icone.fr", "www.marque-icone.com"])
    }

    /// The suffix hop is for the home page only, never to another name, never to a private address.
    @Test func otherSuffixHopsAreRefused() async throws {
        let (session, _) = Self.makeSession()
        for host in ["www.marque-autre.com", "www.prive-marque.com", "cdn.image-marque.com"] {
            StubProtocol.install(host: host) { request in
                switch request.url?.path {
                case "", "/": .init(body: Data(#"<link rel="apple-touch-icon" href="/logo-ios.png">"#.utf8))
                default: .init(body: Self.pngData(side: 180))
                }
            }
        }
        // Another name: refused.
        StubProtocol.install(host: "www.marque-saut.fr") { _ in
            .init(status: 301, headers: ["Location": "https://www.marque-autre.com/"])
        }
        // Same name, private address: refused before the hop.
        StubProtocol.install(host: "www.prive-marque.fr") { _ in
            .init(status: 301, headers: ["Location": "https://www.prive-marque.com/"])
        }
        // Same name, but from an image, not the home page: refused.
        StubProtocol.install(host: "www.image-marque.fr") { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(#"<link rel="apple-touch-icon" href="/logo-ios.png">"#.utf8))
            case "/logo-ios.png": .init(status: 302, headers: ["Location": "https://cdn.image-marque.com/logo-ios.png"])
            default: .init(status: 404)
            }
        }
        for host in ["marque-saut.fr", "prive-marque.fr", "image-marque.fr"] {
            StubProtocol.install(host: host) { _ in .init(status: 404) }
        }
        let resolver = StaticResolver(["www.prive-marque.com": ["10.0.0.3"]])
        let loader = SiteIconLoader(cacheDirectory: Self.tempDirectory(), session: session, resolver: resolver, enabled: { true })
        #expect(await loader.icon(for: "https://www.marque-saut.fr") == nil)
        #expect(await loader.icon(for: "https://www.prive-marque.fr") == nil)
        #expect(await loader.icon(for: "https://www.image-marque.fr") == nil)
        #expect(StubProtocol.requests(host: "www.marque-autre.com").isEmpty)
        #expect(StubProtocol.requests(host: "www.prive-marque.com").isEmpty)
        #expect(StubProtocol.requests(host: "cdn.image-marque.com").isEmpty)
    }
}
