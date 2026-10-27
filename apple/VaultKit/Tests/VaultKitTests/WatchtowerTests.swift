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

        let offline = try await session.watchtowerReport(ranges: nil, twofaDirectory: nil, passkeysDirectory: nil)
        #expect(offline.pwned == .disabled)
        #expect(offline.missingPrefixes.isEmpty)
        let reused = offline.checks.first { $0.check == "reused" }
        #expect(Set(reused?.itemIds ?? []) == [a.id, b.id])

        let first = try await session.watchtowerReport(ranges: [], twofaDirectory: nil, passkeysDirectory: nil)
        #expect(first.missingPrefixes == ["5BAA6"])
        #expect(first.pwned == .unavailable)

        let body = Data("1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n".utf8)
        let second = try await session.watchtowerReport(
            ranges: [FfiRangeResponse(prefix: "5BAA6", body: body)], twofaDirectory: nil, passkeysDirectory: nil)
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
        let report = try await session.watchtowerReport(ranges: nil, twofaDirectory: nil, passkeysDirectory: nil)
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

    @Test func catalogsStayOfflineWhenNetworkIsNotAllowed() async {
        WatchtowerStubProtocol.reset()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [WatchtowerStubProtocol.self]
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fetcher = WatchtowerFetcher(session: URLSession(configuration: config), cacheDirectory: dir)
        let none = await fetcher.siteDirectories(allowNetwork: false)
        #expect(none.twofa == nil && none.passkeys == nil)
        #expect(WatchtowerStubProtocol.paths().isEmpty)
        let fetched = await fetcher.siteDirectories(allowNetwork: true)
        #expect(fetched.twofa != nil && fetched.passkeys != nil)
        let cached = await fetcher.siteDirectories(allowNetwork: false)
        #expect(cached.twofa == fetched.twofa)
        #expect(WatchtowerStubProtocol.paths().count == 2)
    }
}

/// Answers every request with a small body and records what was asked.
final class WatchtowerStubProtocol: URLProtocol, @unchecked Sendable {
    private static let log = Mutex<[(path: String, padding: String?)]>([])

    static func reset() { log.withLock { $0.removeAll() } }
    static func paths() -> [String] { log.withLock { $0.map(\.path) } }
    static func paddingHeaders() -> [String?] { log.withLock { $0.map(\.padding) } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let path = request.url?.path ?? ""
        let padding = request.value(forHTTPHeaderField: "Add-Padding")
        Self.log.withLock { $0.append((path, padding)) }
        let body = path.hasPrefix("/range/") ? Data("0000000000000000000000000000000000A:0\n".utf8) : Data("{}".utf8)
        if let url = request.url, let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil) {
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        }
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
