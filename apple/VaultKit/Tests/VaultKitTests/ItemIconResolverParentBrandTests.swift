import Foundation
import Testing

@testable import VaultKit

/// A derived site shows its parent brand's logo: by the name its home page gives itself first, by
/// a domain it links to only when it has no icon of its own it may show.
@Suite struct ItemIconResolverParentBrandTests {
    static let bay = Data("bayclub-icon".utf8)
    static let acme = Data("acme-icon".utf8)
    static let brand = Data("brand-icon".utf8)
    static let social = Data("facebook-icon".utf8)
    static let login = Data("login-icon".utf8)

    /// A pack of five icons: bayclub, acme and "login" by name, brandclub.com and facebook.com by
    /// domain.
    static func packData(version: Int, rejects: [String]? = nil) -> Data {
        makeIconPack(
            version: version, icons: [(bay, 0), (acme, 0), (brand, 0), (social, 0), (login, 0)],
            domains: ["brandclub.com": 2, "facebook.com": 3, "autre.fr": 1],
            names: ["bayclub": 0, "acme": 1, "login": 4], rejects: rejects)
    }

    static func make(version: Int = 7, rejects: [String]? = nil, cache: URL = SiteIconLoaderTests.tempDirectory())
        throws -> ItemIconResolver
    {
        let (session, _) = SiteIconLoaderTests.makeSession()
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("parent-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let baseline = folder.appendingPathComponent("pack.bin")
        try packData(version: version, rejects: rejects).write(to: baseline)
        let store = IconPackStore(baseline: baseline, directory: folder.appendingPathComponent("dl"))
        let site = SiteIconLoader(
            cacheDirectory: cache, session: session, resolver: StaticResolver(), enabled: { true },
            rejects: { store.pack()?.rejects ?? [] }, pack: { store.pack() })
        return ItemIconResolver(pack: store, site: site, enabled: { true })
    }

    /// Serves `html` as the home page of `host` and `favicon` at its well-known paths.
    static func serve(_ host: String, html: String, favicon: Data?) {
        StubProtocol.install(host: host) { request in
            switch request.url?.path {
            case "", "/": .init(body: Data(html.utf8))
            case "/apple-touch-icon.png", "/favicon.ico": favicon.map { .init(body: $0) } ?? .init(status: 404)
            default: .init(status: 404)
            }
        }
    }

    // MARK: Names

    @Test func brandNameRule() throws {
        let pack = try IconPack(data: Self.packData(version: 1))
        #expect(pack.icon(forBrandName: "Bay Club Connect")?.data == Self.bay)
        #expect(pack.icon(forBrandName: "Bay Club Member Portal")?.data == Self.bay)
        #expect(pack.icon(forBrandName: "My Acme App")?.data == Self.acme)
        #expect(pack.icon(forBrandName: "ACME")?.data == Self.acme)
        // Three generic words, a generic word in the middle, a page name: no match.
        #expect(pack.icon(forBrandName: "Bay Club Member Portal Login") == nil)
        #expect(pack.icon(forBrandName: "Bay Connect Club") == nil)
        #expect(pack.icon(forBrandName: "Login") == nil)
        #expect(pack.icon(forBrandName: "Sign In") == nil)
        #expect(pack.icon(forBrandName: "") == nil)
        #expect(IconPack.brandKeys("Bay Club Member Portal") == ["bayclubmemberportal", "bayclubmember", "bayclub"])
        // Under four characters: never.
        #expect(IconPack.brandKeys("Abc Portal") == ["abcportal"])
        #expect(IconPack.brandKeys("Abcd").isEmpty == false)
        #expect(IconPack.brandKeys("Abc").isEmpty)
        #expect(IconPack.brandKeys(SiteIconLoader.decodeEntities("Bay Club &amp; Spa")).first == "bayclubandspa")
    }

    // MARK: Resolver order

    /// The Bay Club case: the portal's og:site_name names the brand, which beats the platform
    /// favicon the portal serves.
    @Test func bayClubConnectShowsBayClub() async throws {
        let resolver = try Self.make()
        let url = "https://members.bayclub-connect-test.com/login"
        Self.serve(
            "members.bayclub-connect-test.com",
            html: #"<title>Welcome</title><meta property="og:site_name" content="Bay Club Connect">"#,
            favicon: SiteIconLoaderTests.patternPNG(seed: 11))
        // No title: the pack's title lookup (an earlier step) would find Bay Club by itself.
        #expect(await resolver.icon(for: url, title: "") == Self.bay)
        #expect(resolver.cachedIcon(for: url, title: "") == Self.bay)
    }

    @Test func titleBeforeItsSeparatorNamesTheBrand() async throws {
        let resolver = try Self.make()
        Self.serve("portal.acme-members-test.com", html: "<title>Acme | Member Portal</title>", favicon: nil)
        #expect(await resolver.icon(for: "https://portal.acme-members-test.com", title: "") == Self.acme)
        Self.serve("clubs.bay-member-test.com", html: "<title>Bay Club Member Portal</title>", favicon: nil)
        #expect(await resolver.icon(for: "https://clubs.bay-member-test.com", title: "") == Self.bay)
    }

    @Test func genericTitleGivesNoParentBrand() async throws {
        let resolver = try Self.make()
        let site = SiteIconLoaderTests.patternPNG(seed: 12)
        Self.serve("www.login-only-test.com", html: "<title>Login</title>", favicon: site)
        let shown = try #require(await resolver.icon(for: "https://www.login-only-test.com", title: ""))
        #expect(shown != Self.login)
        #expect(resolver.site.cachedParentBrand(for: "https://www.login-only-test.com")?.byName == nil)
    }

    /// No name match, the favicon is the platform's: the brand the portal links to shows.
    @Test func linkedBrandShowsWhenTheSiteIconIsRejected() async throws {
        let platform = SiteIconLoaderTests.patternPNG(seed: 13)
        let reject = String(format: "%016llx", try SiteIconLoaderTests.rejectHash(platform))
        let resolver = try Self.make(rejects: [reject])
        let html = """
            <title>Members</title><a href="https://brandclub.com/">home</a><a href="https://www.brandclub.com/x">x</a>
            <a href="https://facebook.com/a">f</a><a href="https://facebook.com/b">f</a><a href="https://facebook.com/c">f</a>
            """
        Self.serve("brandclub-portal-test.com", html: html, favicon: platform)
        let url = "https://brandclub-portal-test.com/signin"
        #expect(await resolver.icon(for: url, title: "") == Self.brand)
        #expect(resolver.cachedIcon(for: url, title: "") == Self.brand)
    }

    /// A site icon it may show wins over a linked brand.
    @Test func linkedBrandIsNotUsedWhenTheSiteHasAnIcon() async throws {
        let resolver = try Self.make()
        let own = SiteIconLoaderTests.patternPNG(seed: 14)
        Self.serve("brandclub-shop-test.com", html: #"<a href="https://brandclub.com/">home</a>"#, favicon: own)
        let shown = try #require(await resolver.icon(for: "https://brandclub-shop-test.com", title: ""))
        #expect(shown != Self.brand)
        #expect(resolver.site.cachedParentBrand(for: "https://brandclub-shop-test.com")?.byLink == 2)
        #expect(resolver.cachedIcon(for: "https://brandclub-shop-test.com", title: "") == shown)
    }

    /// Social networks and the like never stand for the brand, even as the canonical address.
    @Test func excludedLinkedHostsAreIgnored() async throws {
        let platform = SiteIconLoaderTests.patternPNG(seed: 15)
        let reject = String(format: "%016llx", try SiteIconLoaderTests.rejectHash(platform))
        let resolver = try Self.make(rejects: [reject])
        let html = """
            <link rel="canonical" href="https://www.facebook.com/club"><a href="https://facebook.com/club">f</a>
            """
        Self.serve("facebookfans-club-test.com", html: html, favicon: platform)
        #expect(await resolver.icon(for: "https://facebookfans-club-test.com", title: "") == nil)
    }

    /// A parent brand found in another pack version is not used; the site is searched again.
    @Test func newPackVersionLooksForTheParentBrandAgain() async throws {
        let cache = SiteIconLoaderTests.tempDirectory()
        let url = "https://members.bay-version-test.com"
        Self.serve("members.bay-version-test.com", html: #"<meta property="og:site_name" content="Bay Club Connect">"#,
            favicon: SiteIconLoaderTests.patternPNG(seed: 16))
        let old = try Self.make(version: 7, cache: cache)
        #expect(await old.icon(for: url, title: "") == Self.bay)
        let count = StubProtocol.requests(host: "members.bay-version-test.com").count

        let newer = try Self.make(version: 8, cache: cache)
        #expect(newer.cachedIcon(for: url, title: "") != Self.bay)
        #expect(await newer.icon(for: url, title: "") != nil)
        await newer.site.settle()
        #expect(StubProtocol.requests(host: "members.bay-version-test.com").count > count)
        #expect(newer.site.cachedParentBrand(for: url)?.packVersion == 8)
        #expect(newer.cachedIcon(for: url, title: "") == Self.bay)
    }
}
