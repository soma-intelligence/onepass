import Foundation
import Testing

@testable import VaultKit

/// A site icon cached before the pack knew its platform's hash is not shown either.
@Suite struct ItemIconResolverRejectTests {
    @Test func cachedPlatformIconIsNotShown() async throws {
        let (session, _) = SiteIconLoaderTests.makeSession()
        let platform = SiteIconLoaderTests.patternPNG(seed: 1), brand = SiteIconLoaderTests.patternPNG(seed: 2)
        StubProtocol.install(host: "portail.gym-exemple.fr") { request in
            request.url?.path == "/apple-touch-icon.png" ? .init(body: platform) : .init(status: 404)
        }
        StubProtocol.install(host: "www.marque-exemple.fr") { request in
            request.url?.path == "/apple-touch-icon.png" ? .init(body: brand) : .init(status: 404)
        }
        // Fetched and cached by a loader that knew no reject (an older pack).
        let site = SiteIconLoader(
            cacheDirectory: SiteIconLoaderTests.tempDirectory(), session: session, resolver: StaticResolver(),
            enabled: { true })
        #expect(await site.icon(for: "https://portail.gym-exemple.fr") != nil)
        #expect(await site.icon(for: "https://www.marque-exemple.fr") != nil)

        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("rejects-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let baseline = folder.appendingPathComponent("pack.bin")
        let reject = String(format: "%016llx", try SiteIconLoaderTests.rejectHash(platform))
        try makeIconPack(version: 5, icons: [(Data("x".utf8), 0)], domains: ["autre.fr": 0], rejects: [reject])
            .write(to: baseline)
        let resolver = ItemIconResolver(
            pack: IconPackStore(baseline: baseline, directory: folder.appendingPathComponent("dl")), site: site,
            enabled: { true })
        #expect(resolver.cachedIcon(for: "https://portail.gym-exemple.fr/login", title: "Ma salle") == nil)
        #expect(resolver.cachedIcon(for: "https://portail.gym-exemple.fr/login", title: "Ma salle") == nil)
        #expect(await resolver.icon(for: "https://portail.gym-exemple.fr", title: "Ma salle") == nil)
        #expect(resolver.cachedIcon(for: "https://www.marque-exemple.fr", title: "Marque") != nil)
        #expect(await resolver.icon(for: "https://www.marque-exemple.fr", title: "Marque") != nil)
    }
}
