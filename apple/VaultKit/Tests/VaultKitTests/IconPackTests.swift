import CoreGraphics
import CryptoKit
import Foundation
import Testing

@testable import VaultKit

/// A pack in format 1, as `scripts/icon_pack.py` writes it.
func makeIconPack(
    version: Int, icons: [(Data, Int)], domains: [String: Int], size: Int = 256, names: [String: Int]? = nil,
    tenants: [String]? = nil
) -> Data {
    var offsets: [[Int]] = []
    var blob = Data()
    for (data, flags) in icons {
        offsets.append([blob.count, data.count, flags])
        blob.append(data)
    }
    var index: [String: Any] = ["format": 1, "version": version, "size": size, "icons": offsets, "domains": domains]
    if let names { index["names"] = names }
    if let tenants { index["tenants"] = tenants }
    let json = try! JSONSerialization.data(withJSONObject: index, options: [.sortedKeys])
    var out = Data("OPIP".utf8)
    out.append(1)
    out.append(contentsOf: withUnsafeBytes(of: UInt32(json.count).bigEndian, Array.init))
    out.append(json)
    out.append(blob)
    return out
}

/// Serves fixed bodies by URL path, counts requests.
final class IconPackStub: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var bodies: [String: Data] = [:]
    nonisolated(unsafe) static var requests: [String] = []
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path = request.url?.lastPathComponent ?? ""
        Self.lock.lock()
        Self.requests.append(request.url?.absoluteString ?? "")
        let body = Self.bodies[path]
        Self.lock.unlock()
        let status = body == nil ? 404 : 200
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body ?? Data())
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@Suite("IconPack", .serialized)
struct IconPackTests {
    let red = Data("red-webp".utf8)
    let mark = Data("mark-webp".utf8)

    @Test func parsesAndLooksUpByHostThenParents() throws {
        let pack = try IconPack(data: makeIconPack(
            version: 7, icons: [(red, 0), (mark, 1)],
            domains: ["withings.com": 0, "apple.com": 1, "firefox.com": 0, "service.gov.uk": 1]))
        #expect(pack.version == 7)
        #expect(pack.icon(forHost: "withings.com")?.data == red)
        #expect(pack.icon(forHost: "WWW.Withings.com.")?.data == red)
        #expect(pack.icon(forHost: "account.withings.com")?.data == red)
        #expect(pack.icon(forHost: "appleid.apple.com") == IconPack.Icon(data: mark, monochrome: true))
        #expect(pack.icon(forHost: "accounts.firefox.com")?.monochrome == false)
        #expect(pack.icon(forHost: "withings.fr") == nil)
        #expect(pack.icon(forHost: "com") == nil)
        // A shared suffix is never reached by stripping labels.
        #expect(pack.icon(forHost: "other.gov.uk") == nil)
        #expect(pack.icon(forHost: "x.service.gov.uk")?.data == mark)
    }

    @Test func refusesMalformedPacks() {
        let good = makeIconPack(version: 1, icons: [(red, 0)], domains: ["a.com": 0])
        #expect(throws: IconPack.Problem.notAPack) { try IconPack(data: Data("NOPE".utf8) + good.dropFirst(4)) }
        #expect(throws: IconPack.Problem.outOfBounds) { try IconPack(data: good.dropLast(2)) }
        #expect(throws: IconPack.Problem.outOfBounds) {
            try IconPack(data: makeIconPack(version: 1, icons: [(red, 0)], domains: ["a.com": 3]))
        }
        #expect(throws: IconPack.Problem.notAPack) { try IconPack(data: Data()) }
        var badIndex = good
        badIndex[12] = UInt8(ascii: "!")
        #expect(throws: IconPack.Problem.malformedIndex) { try IconPack(data: badIndex) }
    }

    @Test func manifestNeedsTheTrustedSignatureAndAPlainFileName() throws {
        let key = Curve25519.Signing.PrivateKey()
        let other = Curve25519.Signing.PrivateKey()
        let body = Data(#"{"format":1,"version":9,"pack":{"file":"onepass-icons-9.bin","size":10,"sha256":"\#(String(repeating: "a", count: 64))"}}"#.utf8)
        let signature = Data(try key.signature(for: body).base64EncodedString().utf8)
        let manifest = try IconPackManifest.verified(body, signature: signature, publicKey: key.publicKey.rawRepresentation)
        #expect(manifest.version == 9)
        #expect(throws: IconPackManifest.Problem.badSignature) {
            try IconPackManifest.verified(body, signature: signature, publicKey: other.publicKey.rawRepresentation)
        }
        var tampered = body
        tampered[tampered.startIndex + 30] = UInt8(ascii: "8")
        #expect(throws: IconPackManifest.Problem.badSignature) {
            try IconPackManifest.verified(tampered, signature: signature, publicKey: key.publicKey.rawRepresentation)
        }
        let escaping = Data(#"{"format":1,"version":9,"pack":{"file":"../evil.bin","size":10,"sha256":"\#(String(repeating: "a", count: 64))"}}"#.utf8)
        let escapingSignature = Data(try key.signature(for: escaping).base64EncodedString().utf8)
        #expect(throws: IconPackManifest.Problem.malformed) {
            try IconPackManifest.verified(escaping, signature: escapingSignature, publicKey: key.publicKey.rawRepresentation)
        }
    }

    struct Fixture {
        let key = Curve25519.Signing.PrivateKey()
        let directory = FileManager.default.temporaryDirectory.appending(path: "iconpack-\(UUID().uuidString)")
        let base = URL(string: "https://example.test/releases/download/icon-pack/")!

        func publish(_ pack: Data, version: Int, sizeOverride: Int? = nil, hashOverride: String? = nil) throws {
            let name = "onepass-icons-\(version).bin"
            let hash = hashOverride ?? SHA256.hash(data: pack).map { String(format: "%02x", $0) }.joined()
            let manifest = Data(#"{"format":1,"version":\#(version),"pack":{"file":"\#(name)","size":\#(sizeOverride ?? pack.count),"sha256":"\#(hash)"}}"#.utf8)
            IconPackStub.lock.lock()
            IconPackStub.bodies = [
                "icon-pack-manifest.json": manifest,
                "icon-pack-manifest.json.sig": Data(try key.signature(for: manifest).base64EncodedString().utf8),
                name: pack,
            ]
            IconPackStub.requests = []
            IconPackStub.lock.unlock()
        }

        func store(baseline: URL?, now: Date = Date()) -> IconPackStore {
            let configuration = URLSession.ephemeralNoCookiesConfiguration
            configuration.protocolClasses = [IconPackStub.self]
            return IconPackStore(
                baseline: baseline, directory: directory, publicKey: key.publicKey.rawRepresentation.base64EncodedString(),
                baseURL: base, session: URLSession(configuration: configuration), now: { now })
        }

        func baseline(_ data: Data) throws -> URL {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let url = directory.appending(path: "baseline.bin")
            try data.write(to: url)
            return url
        }
    }

    @Test func refreshSwapsInANewerSignedPack() async throws {
        let f = Fixture()
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let baseline = try f.baseline(makeIconPack(version: 5, icons: [(red, 0)], domains: ["a.com": 0]))
        let newer = makeIconPack(version: 6, icons: [(mark, 1)], domains: ["a.com": 0, "b.com": 0])
        try f.publish(newer, version: 6)
        let store = f.store(baseline: baseline)
        #expect(store.icon(forHost: "b.com") == nil)
        #expect(await store.refreshIfDue() == .updated(version: 6))
        #expect(store.icon(forHost: "b.com")?.data == mark)
        // Only the whole-pack files were asked for, never a site.
        #expect(IconPackStub.requests.allSatisfy { $0.hasPrefix(f.base.absoluteString) })
        #expect(!IconPackStub.requests.contains { $0.contains("a.com") || $0.contains("b.com") })
        // Checked a moment ago: not again for a week.
        #expect(await store.refreshIfDue() == .notDue)
        // A new store reads the downloaded pack, newer than its baseline.
        #expect(f.store(baseline: baseline).pack()?.version == 6)
    }

    @Test func refreshRefusesOlderTamperedOrOversizedPacks() async throws {
        let f = Fixture()
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let baseline = try f.baseline(makeIconPack(version: 5, icons: [(red, 0)], domains: ["a.com": 0]))
        let store = f.store(baseline: baseline)

        try f.publish(makeIconPack(version: 4, icons: [(mark, 0)], domains: ["a.com": 0]), version: 4)
        #expect(await store.refreshIfDue(force: true) == .upToDate)

        let newer = makeIconPack(version: 8, icons: [(mark, 0)], domains: ["a.com": 0])
        try f.publish(newer, version: 8, hashOverride: String(repeating: "0", count: 64))
        #expect(await store.refreshIfDue(force: true) == .failed)

        try f.publish(newer, version: 8, sizeOverride: newer.count - 1)
        #expect(await store.refreshIfDue(force: true) == .failed)

        // A pack whose own version is not the manifest's.
        try f.publish(makeIconPack(version: 3, icons: [(mark, 0)], domains: ["a.com": 0]), version: 8)
        #expect(await store.refreshIfDue(force: true) == .failed)

        #expect(store.pack()?.version == 5)
        #expect(store.icon(forHost: "a.com")?.data == red)
    }

    @Test func noKeyMeansNoRefresh() async {
        let store = IconPackStore(baseline: nil, directory: FileManager.default.temporaryDirectory, publicKey: "")
        #expect(await store.refreshIfDue(force: true) == .disabled)
    }

    @Test func shippedKeyIsEmptyUntilTheFounderCreatesIt() {
        // docs/icon-pack.md: the key is a founder action; no refresh until it is set.
        #expect(IconPackStore.publicKey.isEmpty)
    }

    @Test func shareBaselineCopiesTheShippedPackForTheExtensions() async throws {
        let f = Fixture()
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let shipped = try f.baseline(makeIconPack(version: 5, icons: [(red, 0)], domains: ["a.com": 0]))
        let shared = f.directory.appending(path: "shared")
        let app = IconPackStore(baseline: shipped, directory: shared, publicKey: "")
        #expect(await app.shareBaseline())
        // Already there: not written again.
        #expect(await app.shareBaseline() == false)
        // The extension reads the shared folder alone.
        let extensionStore = IconPackStore(baseline: nil, directory: shared, publicKey: "")
        #expect(extensionStore.icon(forHost: "a.com")?.data == red)
        #expect(extensionStore.pack()?.version == 5)
    }

    @Test func iconSlicesAreStandaloneData() throws {
        let pack = try IconPack(data: makeIconPack(version: 1, icons: [(red, 0), (mark, 1)], domains: ["a.com": 1]))
        let icon = try #require(pack.icon(forHost: "a.com"))
        #expect(icon.data == mark && icon.data.startIndex == 0 && icon.monochrome)
    }
}

/// Same as `IconPackStub`, its own state: the two suites run in parallel and must not reset
/// each other's bodies.
final class ResolverStub: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var bodies: [String: Data] = [:]
    nonisolated(unsafe) static var requests: [String] = []
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path = request.url?.lastPathComponent ?? ""
        Self.lock.lock()
        Self.requests.append(request.url?.absoluteString ?? "")
        let body = Self.bodies[path]
        Self.lock.unlock()
        let status = body == nil ? 404 : 200
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body ?? Data())
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@Suite("ItemIconResolver", .serialized)
struct ItemIconResolverTests {
    let packIcon = Data("pack-webp".utf8)
    let red = Data("red-webp".utf8)
    let mark = Data("mark-webp".utf8)

    @Test func tenantPlatformsKeepTheirIconToThemselves() throws {
        let pack = try IconPack(data: makeIconPack(
            version: 7, icons: [(red, 0), (mark, 0)], domains: ["zendesk.com": 0, "reddit.com": 1],
            tenants: ["zendesk.com"]))
        #expect(pack.icon(forHost: "zendesk.com")?.data == red)
        #expect(pack.icon(forHost: "www.zendesk.com")?.data == red)
        // acme.zendesk.com is Acme's help desk, not Zendesk.
        #expect(pack.icon(forHost: "acme.zendesk.com") == nil)
        #expect(pack.icon(forHost: "old.reddit.com")?.data == mark)
    }

    @Test func titlesFindTheirBrand() throws {
        let pack = try IconPack(data: makeIconPack(
            version: 7, icons: [(red, 0), (mark, 0)], domains: ["reddit.com": 0, "burgerking.com": 1],
            names: ["reddit": 0, "burgerking": 1, "voyageprive": 1]))
        #expect(pack.icon(forTitle: "Reddit")?.data == red)
        #expect(pack.icon(forTitle: " Burger King ")?.data == mark)
        #expect(pack.icon(forTitle: "Voyage Privé")?.data == mark)
        #expect(pack.icon(forTitle: "reddit.com")?.data == red)
        #expect(pack.icon(forTitle: "Reddit perso") == nil)
        #expect(pack.icon(forTitle: "") == nil)
        #expect(IconPack.squash("AT&T Wi-Fi") == "atandtwifi")
        // A name pointing past the icons is refused like a domain.
        #expect(throws: IconPack.Problem.outOfBounds) {
            try IconPack(data: makeIconPack(version: 7, icons: [(red, 0)], domains: [:], names: ["x": 3]))
        }
    }

    func png(side: Int) -> Data {
        SiteIconLoader.squarePNG(side: side, aspect: CGSize(width: 1, height: 1)) { context, rect in
            context.setFillColor(CGColor(red: 1, green: 0, blue: 0, alpha: 1))
            context.fill(rect)
        }!
    }

    func resolver(enabled: Bool, directory: URL) throws -> ItemIconResolver {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let baseline = directory.appending(path: "baseline.bin")
        try makeIconPack(version: 3, icons: [(packIcon, 0)], domains: ["withings.com": 0]).write(to: baseline)
        let configuration = URLSession.ephemeralNoCookiesConfiguration
        configuration.protocolClasses = [ResolverStub.self]
        ResolverStub.lock.lock()
        ResolverStub.bodies = [:]
        ResolverStub.requests = []
        ResolverStub.lock.unlock()
        let site = SiteIconLoader(
            cacheDirectory: directory.appending(path: "site"), session: URLSession(configuration: configuration),
            resolver: StaticResolver(), enabled: { enabled })
        return ItemIconResolver(
            pack: IconPackStore(baseline: baseline, directory: directory.appending(path: "pack"), publicKey: ""),
            site: site, enabled: { enabled })
    }

    @Test func orderIsChosenThenPackThenSharpSiteIcon() {
        let chosen = Data("chosen".utf8)
        let sharp = png(side: 128)
        let blurry = png(side: 96)
        #expect(ItemIconResolver.pick(chosen: chosen, pack: packIcon, site: sharp) == chosen)
        #expect(ItemIconResolver.pick(chosen: nil, pack: packIcon, site: sharp) == packIcon)
        #expect(ItemIconResolver.pick(chosen: nil, pack: nil, site: sharp) == sharp)
        // A 48 px source is stored at 96 px: shown as the monogram tile instead.
        #expect(ItemIconResolver.pick(chosen: nil, pack: nil, site: blurry) == nil)
        #expect(ItemIconResolver.pick(chosen: nil, pack: nil, site: nil) == nil)
    }

    @Test func packHostsAreNeverAskedOfTheirSite() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "resolver-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let icons = try resolver(enabled: true, directory: directory)
        #expect(icons.cachedIcon(for: "https://account.withings.com/login") == packIcon)
        #expect(icons.cachedIcon(for: "withings.com") == packIcon)
        #expect(icons.cachedIcon(for: "http://www.withings.com") == packIcon)
        #expect(await icons.icon(for: "https://app.withings.com") == packIcon)
        await icons.prefetch(["https://withings.com", "https://account.withings.com"])
        let requests = ResolverStub.lock.withLock { ResolverStub.requests }
        #expect(requests.isEmpty)
    }

    @Test func iconsOffShowNothingButTheChosenIcon() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "resolver-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let icons = try resolver(enabled: false, directory: directory)
        #expect(icons.cachedIcon(for: "https://withings.com") == nil)
        #expect(await icons.icon(for: "https://withings.com") == nil)
        let chosen = Data("chosen".utf8)
        #expect(icons.cachedIcon(for: "https://withings.com", chosen: chosen) == chosen)
    }

    @Test func itemsWithoutAnAddressFindTheirBrandByTitle() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "resolver-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let baseline = directory.appending(path: "baseline.bin")
        try makeIconPack(version: 3, icons: [(packIcon, 0)], domains: ["withings.com": 0], names: ["withings": 0])
            .write(to: baseline)
        let site = SiteIconLoader(cacheDirectory: directory.appending(path: "site"), enabled: { true })
        let icons = ItemIconResolver(
            pack: IconPackStore(baseline: baseline, directory: directory.appending(path: "pack"), publicKey: ""),
            site: site, enabled: { true })
        #expect(icons.cachedIcon(for: nil, title: "Withings") == packIcon)
        #expect(icons.cachedIcon(for: nil, title: "Bank") == nil)
        #expect(await icons.icon(for: nil, title: "withings") == packIcon)
        let off = ItemIconResolver(pack: icons.pack, site: site, enabled: { false })
        #expect(off.cachedIcon(for: nil, title: "Withings") == nil)
    }

    @Test func hostParsing() {
        #expect(ItemIconResolver.host(of: " Example.COM/login ") == "example.com")
        #expect(ItemIconResolver.host(of: "http://a.example.com:8080/x") == "a.example.com")
        #expect(ItemIconResolver.host(of: "androidapp://com.example") == nil)
        #expect(ItemIconResolver.host(of: "") == nil)
    }
}
