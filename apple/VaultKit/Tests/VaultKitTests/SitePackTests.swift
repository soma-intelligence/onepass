import CryptoKit
import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// The signed vector of the core (`core/onepass-core/tests/fixtures/site-pack/signed`), read where
/// it lives so that Swift and Rust test the same bytes.
enum SitePackVector {
    static var directory: URL {
        // apple/VaultKit/Tests/VaultKitTests/SitePackTests.swift -> repository root
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return url.appending(path: "core/onepass-core/tests/fixtures/site-pack/signed")
    }

    static func file(_ name: String) throws -> Data { try Data(contentsOf: directory.appending(path: name)) }
    static var pack: Data { get throws { try file("onepass-sites-2026112001.json") } }
    static var manifest: Data { get throws { try file("site-pack-manifest.json") } }
    static var signature: Data { get throws { try file("site-pack-manifest.json.sig") } }
    static var publicKey: String {
        get throws { String(decoding: try file("public-key.b64"), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) }
    }
}

/// A pack in format 1 with one site, as `scripts/site_pack.py` writes it (keys sorted).
func makeSitePack(version: UInt64, site: String = "ovh.com") -> Data {
    Data(#"{"format":1,"sites":{"\#(site)":{"additional_domains":[],"twofa":["totp"]}},"version":\#(version)}"#.utf8)
}

/// Serves fixed bodies by file name and records every URL asked for.
final class SitePackStub: URLProtocol, @unchecked Sendable {
    private static let state = Mutex<(bodies: [String: Data], requests: [String])>(([:], []))

    static func serve(_ bodies: [String: Data]) { state.withLock { $0 = (bodies, []) } }
    static var requests: [String] { state.withLock { $0.requests } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let name = request.url?.lastPathComponent ?? ""
        let body = Self.state.withLock { state in
            state.requests.append(request.url?.absoluteString ?? "")
            return state.bodies[name]
        }
        let response = HTTPURLResponse(
            url: request.url!, statusCode: body == nil ? 404 : 200, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body ?? Data())
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@Suite("SitePack", .serialized)
struct SitePackTests {
    struct Fixture {
        let key = Curve25519.Signing.PrivateKey()
        let directory = FileManager.default.temporaryDirectory.appending(path: "sitepack-\(UUID().uuidString)")
        let base = URL(string: "https://example.test/releases/download/site-pack/")!

        var publicKey: String { key.publicKey.rawRepresentation.base64EncodedString() }

        /// The manifest, its signature and the pack the release would serve.
        func signed(_ pack: Data, version: UInt64, size: Int? = nil) throws -> (manifest: Data, signature: Data) {
            let hash = SHA256.hash(data: pack).map { String(format: "%02x", $0) }.joined()
            let manifest = Data(
                #"{"format":1,"pack":{"file":"onepass-sites-\#(version).json","sha256":"\#(hash)","size":\#(size ?? pack.count)},"version":\#(version)}"#
                    .utf8)
            return (manifest, Data((try key.signature(for: manifest).base64EncodedString() + "\n").utf8))
        }

        func publish(_ pack: Data, version: UInt64, size: Int? = nil) throws {
            let (manifest, signature) = try signed(pack, version: version, size: size)
            SitePackStub.serve([
                "site-pack-manifest.json": manifest,
                "site-pack-manifest.json.sig": signature,
                "onepass-sites-\(version).json": pack,
            ])
        }

        func store(baseline: URL?, publicKey: String? = nil, now: Date = Date()) -> SitePackStore {
            let configuration = URLSession.ephemeralNoCookiesConfiguration
            configuration.protocolClasses = [SitePackStub.self]
            return SitePackStore(
                baseline: baseline, directory: directory, publicKey: publicKey ?? self.publicKey, baseURL: base,
                session: URLSession(configuration: configuration), now: { now })
        }

        func baseline(_ data: Data) throws -> URL {
            let folder = directory.deletingLastPathComponent().appending(path: directory.lastPathComponent + "-app")
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let url = folder.appending(path: "onepass-sites.json")
            try data.write(to: url)
            return url
        }

        func cleanUp() {
            try? FileManager.default.removeItem(at: directory)
            try? FileManager.default.removeItem(
                at: directory.deletingLastPathComponent().appending(path: directory.lastPathComponent + "-app"))
        }
    }

    @Test func noKeyMeansNoRefresh() async throws {
        let f = Fixture()
        defer { f.cleanUp() }
        try f.publish(makeSitePack(version: 9), version: 9)
        let store = f.store(baseline: nil, publicKey: "")
        #expect(await store.refreshIfDue(force: true) == .disabled)
        #expect(SitePackStub.requests.isEmpty)
        // A key of the wrong length counts as no key.
        #expect(await f.store(baseline: nil, publicKey: "AAAA").refreshIfDue(force: true) == .disabled)
    }

    @Test func shippedKeyIsEmptyUntilTheOwnerCreatesIt() {
        // docs/site-pack.md, "Clé de signature": the key is the founder's step; no refresh until it is set.
        #expect(SitePackStore.publicKey.isEmpty)
        #expect(SitePackStore.defaultBaseURL.absoluteString
            == "https://github.com/soma-intelligence/onepass/releases/download/site-pack/")
    }

    @Test func refreshSwapsInANewerSignedPack() async throws {
        let f = Fixture()
        defer { f.cleanUp() }
        let baseline = try f.baseline(makeSitePack(version: 5))
        let newer = makeSitePack(version: 6, site: "github.com")
        try f.publish(newer, version: 6)
        let store = f.store(baseline: baseline)
        #expect(await store.pack() == makeSitePack(version: 5))
        #expect(await store.refreshIfDue() == .updated(version: 6))
        #expect(await store.pack() == newer)
        // Only the whole-pack files were asked for, from the release alone.
        #expect(SitePackStub.requests.map { URL(string: $0)!.lastPathComponent }
            == ["site-pack-manifest.json", "site-pack-manifest.json.sig", "onepass-sites-6.json"])
        #expect(SitePackStub.requests.allSatisfy { $0.hasPrefix(f.base.absoluteString) })
        // Checked a moment ago: not again for a week, then again.
        #expect(await store.refreshIfDue() == .notDue)
        #expect(await f.store(baseline: baseline, now: Date().addingTimeInterval(8 * 24 * 3600)).refreshIfDue()
            == .upToDate)
        // A new store reads the downloaded pack, newer than its baseline, after checking it again.
        #expect(await f.store(baseline: baseline).pack() == newer)
    }

    @Test func refreshAcceptsTheCoreSignedVector() async throws {
        let f = Fixture()
        defer { f.cleanUp() }
        SitePackStub.serve([
            "site-pack-manifest.json": try SitePackVector.manifest,
            "site-pack-manifest.json.sig": try SitePackVector.signature,
            "onepass-sites-2026112001.json": try SitePackVector.pack,
        ])
        let store = f.store(baseline: nil, publicKey: try SitePackVector.publicKey)
        #expect(await store.pack() == nil)
        #expect(await store.refreshIfDue() == .updated(version: 2026112001))
        #expect(await store.pack() == (try SitePackVector.pack))
    }

    @Test func refreshRefusesOlderTamperedOrOversizedPacks() async throws {
        let f = Fixture()
        defer { f.cleanUp() }
        let baseline = try f.baseline(makeSitePack(version: 5))
        let store = f.store(baseline: baseline)

        // Same or older version: nothing downloaded past the manifest.
        try f.publish(makeSitePack(version: 5, site: "github.com"), version: 5)
        #expect(await store.refreshIfDue(force: true) == .upToDate)
        try f.publish(makeSitePack(version: 4, site: "github.com"), version: 4)
        #expect(await store.refreshIfDue(force: true) == .upToDate)
        #expect(!SitePackStub.requests.contains { $0.hasSuffix("onepass-sites-4.json") })

        // A pack that is not the one the manifest names (one byte changed, same size).
        let newer = makeSitePack(version: 8, site: "github.com")
        let (manifest, signature) = try f.signed(newer, version: 8)
        var tampered = newer
        tampered[tampered.firstIndex(of: UInt8(ascii: "g"))!] = UInt8(ascii: "h")
        SitePackStub.serve([
            "site-pack-manifest.json": manifest, "site-pack-manifest.json.sig": signature, "onepass-sites-8.json": tampered,
        ])
        #expect(await store.refreshIfDue(force: true) == .failed)

        // A manifest signed by another key.
        let other = Fixture()
        try other.publish(newer, version: 8)
        #expect(await store.refreshIfDue(force: true) == .failed)

        // A pack larger than its manifest says: the download stops at the declared size.
        try f.publish(newer, version: 8, size: newer.count - 1)
        #expect(await store.refreshIfDue(force: true) == .failed)

        // A manifest that announces more than a pack may weigh: refused before any download.
        try f.publish(newer, version: 8, size: 16 * 1024 * 1024 + 1)
        #expect(await store.refreshIfDue(force: true) == .failed)
        #expect(!SitePackStub.requests.contains { $0.hasSuffix("onepass-sites-8.json") })

        // A pack whose own version is not the manifest's.
        try f.publish(makeSitePack(version: 3, site: "github.com"), version: 8)
        #expect(await store.refreshIfDue(force: true) == .failed)

        #expect(await store.pack() == makeSitePack(version: 5))
        #expect(await f.store(baseline: baseline).pack() == makeSitePack(version: 5))
    }

    /// An app update ships a pack newer than the one downloaded under the previous version.
    @Test func bundledPackWinsWhenNewerThanTheDownload() async throws {
        let f = Fixture()
        defer { f.cleanUp() }
        let downloaded = makeSitePack(version: 6, site: "github.com")
        try f.publish(downloaded, version: 6)
        #expect(await f.store(baseline: try f.baseline(makeSitePack(version: 5))).refreshIfDue() == .updated(version: 6))

        let shipped = makeSitePack(version: 7)
        let store = f.store(baseline: try f.baseline(shipped))
        #expect(await store.pack() == shipped)
        // The release still serves 6: older than the pack in use.
        #expect(await store.refreshIfDue(force: true) == .upToDate)
        #expect(await store.pack() == shipped)
    }

    @Test func downloadedPackIsVerifiedAgainAtLoad() async throws {
        let f = Fixture()
        defer { f.cleanUp() }
        let shipped = makeSitePack(version: 5)
        let baseline = try f.baseline(shipped)
        try f.publish(makeSitePack(version: 6, site: "github.com"), version: 6)
        #expect(await f.store(baseline: baseline).refreshIfDue() == .updated(version: 6))

        // The stored pack changed on disk (same size): its manifest no longer matches it.
        let stored = f.directory.appending(path: "onepass-sites.json")
        var bytes = try Data(contentsOf: stored)
        bytes[bytes.firstIndex(of: UInt8(ascii: "g"))!] = UInt8(ascii: "h")
        try bytes.write(to: stored)
        #expect(await f.store(baseline: baseline).pack() == shipped)
        // Nor is a download trusted without the key that signed it.
        try makeSitePack(version: 6, site: "github.com").write(to: stored)
        #expect(await f.store(baseline: baseline, publicKey: "").pack() == shipped)
        #expect(await f.store(baseline: baseline).pack() == makeSitePack(version: 6, site: "github.com"))
    }
}
