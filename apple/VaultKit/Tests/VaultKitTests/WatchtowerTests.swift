import CryptoKit
import Foundation
import Synchronization
import Testing

@testable import VaultKit

@MainActor
@Suite("Watchtower", .serialized)
struct WatchtowerTests {
    private func unlockedSession(_ h: SessionHarness) async throws -> VaultSession {
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        return session
    }

    private func addLogin(_ session: VaultSession, title: String, password: String) async throws -> FfiItem {
        var item = try session.newItem(type: .login, vaultID: session.allVaults[0].id)
        item.title = title
        for s in item.sections.indices {
            for f in item.sections[s].fields.indices where item.sections[s].fields[f].kind == .password {
                item.sections[s].fields[f].value = .password(value: password)
            }
        }
        fillRequired(&item)
        return try await session.save(item)
    }

    @Test func offlinePassListsPrefixesThenRangesFindTheBreach() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        let a = try await addLogin(session, title: "A", password: "password")
        let b = try await addLogin(session, title: "B", password: "password")

        let offline = try await session.watchtowerReport(ranges: nil, sitePack: nil)
        #expect(offline.pwned == .disabled)
        #expect(offline.missingPrefixes.isEmpty)
        let reused = offline.checks.first { $0.check == "reused" }
        #expect(Set(reused?.itemIds ?? []) == [a.id, b.id])

        let first = try await session.watchtowerReport(ranges: [], sitePack: nil)
        #expect(first.missingPrefixes == ["5BAA6"])
        #expect(first.pwned == .unavailable)

        let body = Data("1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n".utf8)
        let second = try await session.watchtowerReport(
            ranges: [FfiRangeResponse(prefix: "5BAA6", body: body)], sitePack: nil)
        #expect(second.pwned == .checked)
        let compromised = second.checks.first { $0.check == "compromised" }
        #expect(Set(compromised?.itemIds ?? []) == [a.id, b.id])
    }

    @Test func hiddenVaultsAreLeftOut() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        let item = try await addLogin(session, title: "A", password: "azerty")
        try await session.createVault(
            FfiVaultMeta(name: "Famille", icon: "house", color: "blue", travelSafe: false, mcpAccess: false))
        session.setVaultHidden(item.vaultId, hidden: true)
        let report = try await session.watchtowerReport(ranges: nil, sitePack: nil)
        #expect(report.itemsAnalyzed == 0)
        #expect(report.score == 100)
    }

    @Test func onlyAFiveHexPrefixMakesARequest() {
        #expect(WatchtowerFetcher.isValidPrefix("5BAA6"))
        #expect(!WatchtowerFetcher.isValidPrefix("5baa6"))
        #expect(!WatchtowerFetcher.isValidPrefix("5BAA61"))
        #expect(!WatchtowerFetcher.isValidPrefix("5BA/6"))
        #expect(WatchtowerFetcher.rangeRequest(prefix: "../x") == nil)
        let request = WatchtowerFetcher.rangeRequest(prefix: "5BAA6")
        #expect(request?.url?.absoluteString == "https://api.pwnedpasswords.com/range/5BAA6")
        #expect(request?.value(forHTTPHeaderField: "Add-Padding") == "true")
    }

    @Test func rangesAreFetchedOnceAndKeptUntilCleared() async {
        WatchtowerStubProtocol.reset()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [WatchtowerStubProtocol.self]
        let fetcher = WatchtowerFetcher(session: URLSession(configuration: config), cacheDirectory: nil)
        let first = await fetcher.ranges(for: ["5BAA6", "ABCDE", "not-a-prefix"])
        #expect(Set(first.map(\.prefix)) == ["5BAA6", "ABCDE"])
        #expect(WatchtowerStubProtocol.paths().sorted() == ["/range/5BAA6", "/range/ABCDE"])
        #expect(WatchtowerStubProtocol.paddingHeaders().allSatisfy { $0 == "true" })
        _ = await fetcher.ranges(for: ["5BAA6"])
        #expect(WatchtowerStubProtocol.paths().count == 2)
        await fetcher.clear()
        _ = await fetcher.ranges(for: ["5BAA6"])
        #expect(WatchtowerStubProtocol.paths().count == 3)
    }

    /// The site pack runs the 2FA and passkey checks with breach lookups off (`ranges` nil): they
    /// no longer wait for "Vérifier les fuites".
    @Test func siteChecksRunWithoutTheBreachSetting() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        var item = try await addLogin(session, title: "OVH", password: "Tq7#vLr9-pXw2!mZ8kEa-Hs4")
        item.urls = [FfiUrl(label: "", url: "https://ovh.com", rule: .domain, primary: true)]
        item = try await session.save(item)

        let without = try await session.watchtowerReport(ranges: nil, sitePack: nil)
        #expect(!without.sitesChecked)
        let report = try await session.watchtowerReport(ranges: nil, sitePack: try SitePackVector.pack)
        #expect(report.pwned == .disabled)
        #expect(report.sitesChecked)
        let missing = report.checks.first { $0.check == "missing_2fa" }
        #expect(missing?.itemIds == [item.id])
        #expect(missing?.siteLinks.map(\.host) == ["ovh.com"])
    }

    /// Breach lookups and the site pack refresh: no request reaches 2fa.directory.
    @Test func noSiteDirectoryIsDownloaded() async throws {
        WatchtowerStubProtocol.reset()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [WatchtowerStubProtocol.self]
        let session = URLSession(configuration: config)
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fetcher = WatchtowerFetcher(session: session, cacheDirectory: dir)
        _ = await fetcher.ranges(for: ["5BAA6"])
        _ = await fetcher.breachCatalog(allowNetwork: true)
        let store = SitePackStore(
            baseline: nil, directory: dir.appending(path: "SitePack"),
            publicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString(),
            session: session)
        _ = await store.refreshIfDue(force: true)
        let hosts = WatchtowerStubProtocol.hosts()
        #expect(Set(hosts) == ["api.pwnedpasswords.com", "haveibeenpwned.com", "github.com"])
        #expect(!hosts.contains { $0 == "2fa.directory" || $0.hasSuffix(".2fa.directory") })
    }
}

/// Answers every request with a small body and records what was asked.
final class WatchtowerStubProtocol: URLProtocol, @unchecked Sendable {
    private static let log = Mutex<[(host: String, path: String, padding: String?)]>([])

    static func reset() { log.withLock { $0.removeAll() } }
    static func hosts() -> [String] { log.withLock { $0.map(\.host) } }
    static func paths() -> [String] { log.withLock { $0.map(\.path) } }
    static func paddingHeaders() -> [String?] { log.withLock { $0.map(\.padding) } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let path = request.url?.path ?? ""
        let padding = request.value(forHTTPHeaderField: "Add-Padding")
        Self.log.withLock { $0.append((request.url?.host() ?? "", path, padding)) }
        let body = path.hasPrefix("/range/") ? Data("0000000000000000000000000000000000A:0\n".utf8) : Data("{}".utf8)
        if let url = request.url, let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil) {
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        }
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
