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

    static let daxko = Data("daxko-icon".utf8)
    static let desk = Data("zendesk-icon".utf8)

    /// A pack of seven icons: bayclub, acme, "login" and daxko by name, brandclub.com, facebook.com,
    /// daxko.com (a platform) and zendesk.com (a tenant) by domain.
    static func packData(version: Int, rejects: [String]? = nil) -> Data {
        var body = makeIconPack(
            version: version, icons: [(bay, 0), (acme, 0), (brand, 0), (social, 0), (login, 0), (daxko, 0), (desk, 0)],
            domains: ["brandclub.com": 2, "facebook.com": 3, "autre.fr": 1, "daxko.com": 5, "zendeskclub.com": 6],
            names: ["bayclub": 0, "acme": 1, "login": 4, "daxko": 5, "zendeskclub": 6], tenants: ["zendeskclub.com"],
            rejects: rejects)
        // The `platforms` key, as `scripts/icon_pack.py` writes it.
        body = withPlatforms(body, [5])
        return body
    }

    /// `data` with `"platforms": numbers` added to its index.
    static func withPlatforms(_ data: Data, _ numbers: [Int]) -> Data {
        let length = data[5..<9].reduce(0) { $0 << 8 | Int($1) }
        var index = try! JSONSerialization.jsonObject(with: data[9..<(9 + length)]) as! [String: Any]
        index["platforms"] = numbers
        let json = try! JSONSerialization.data(withJSONObject: index, options: [.sortedKeys])
        var out = Data("OPIP".utf8)
        out.append(1)
        out.append(contentsOf: withUnsafeBytes(of: UInt32(json.count).bigEndian, Array.init))
        out.append(json)
        out.append(data[(9 + length)...])
        return out
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
        // Only generic words: no brand at all.
        for name in ["My Portal", "Member Portal", "Mobile App", "My Account", "Members", "Web"] {
            #expect(IconPack.brandKeys(name).isEmpty, "\(name)")
        }
        #expect(IconPack.brandKeys(SiteIconLoader.decodeEntities("Bay Club &amp; Spa")).first == "bayclubandspa")
    }

    @Test func platformsKeyIsReadAndChecked() throws {
        let pack = try IconPack(data: Self.packData(version: 1))
        #expect(pack.platformIcons == [5])
        #expect(!pack.mayBeParentBrand(5))
        #expect(!pack.mayBeParentBrand(6))
        #expect(pack.mayBeParentBrand(0))
        // A pack's own domain still shows the platform's icon.
        #expect(pack.icon(forHost: "daxko.com")?.data == Self.daxko)
        let plain = try IconPack(data: makeIconPack(version: 1, icons: [(Self.bay, 0)], domains: ["a.fr": 0]))
        #expect(plain.platformIcons.isEmpty)
        #expect(throws: IconPack.Problem.outOfBounds) {
            try IconPack(data: Self.withPlatforms(makeIconPack(version: 1, icons: [(Self.bay, 0)], domains: ["a.fr": 0]), [3]))
        }
    }

    /// The pack names the platforms: a portal calling itself after its software, or pointing its
    /// canonical address at it, gets no parent brand.
    @Test func platformBrandIsNeverAParentBrand() throws {
        let pack = try IconPack(data: Self.packData(version: 1))
        let daxko = Data(#"<meta property="og:site_name" content="Daxko"><title>Daxko Connect</title>"#.utf8)
        #expect(SiteIconLoader.parentBrand(page: daxko, manifest: nil, host: "members.gym-test.com", pack: pack)
            == SiteIconLoader.ParentBrand(packVersion: 1, byName: nil, byLink: nil))
        let canonical = Data(#"<link rel="canonical" href="https://www.daxko.com/members">"#.utf8)
        #expect(SiteIconLoader.parentBrand(page: canonical, manifest: nil, host: "members.gym-test.com", pack: pack).byLink == nil)
        let tenant = Data(#"<title>Zendesk Club</title><link rel="canonical" href="https://zendeskclub.com/">"#.utf8)
        #expect(SiteIconLoader.parentBrand(page: tenant, manifest: nil, host: "help.gym-test.com", pack: pack).isEmpty)
        let bay = Data(#"<meta property="og:site_name" content="Bay Club Connect">"#.utf8)
        #expect(SiteIconLoader.parentBrand(page: bay, manifest: nil, host: "members.gym-test.com", pack: pack).byName == 0)
    }

    /// A rejected (platform) icon in the pack is never a parent brand either.
    @Test func rejectedPackIconIsNeverAParentBrand() throws {
        let platform = SiteIconLoaderTests.patternPNG(seed: 21)
        let reject = String(format: "%016llx", try SiteIconLoaderTests.rejectHash(platform))
        let png = try #require(SiteIconLoader.normalizedPNG(platform))
        let pack = try IconPack(data: makeIconPack(
            version: 1, icons: [(png, 0)], domains: ["vendor.com": 0], names: ["vendor": 0], rejects: [reject]))
        #expect(!pack.mayBeParentBrand(0))
        let page = Data(#"<meta property="og:site_name" content="Vendor">"#.utf8)
        #expect(SiteIconLoader.parentBrand(page: page, manifest: nil, host: "club.vendor-test.com", pack: pack).isEmpty)
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

    /// A new pack re-searches cached hosts for their parent brand a few at a time, each once.
    @Test func parentBrandReSearchesAreBounded() async throws {
        let cache = SiteIconLoaderTests.tempDirectory()
        let hosts = (1...12).map { "club\($0).burst-test.com" }
        for host in hosts {
            Self.serve(host, html: #"<meta property="og:site_name" content="Bay Club Connect">"#,
                favicon: SiteIconLoaderTests.patternPNG(seed: 30))
        }
        let old = try Self.make(version: 7, cache: cache)
        for host in hosts { _ = await old.icon(for: "https://" + host, title: "") }
        let newer = try Self.make(version: 8, cache: cache)
        for _ in 0..<2 {
            for host in hosts { _ = await newer.site.icon(for: "https://" + host) }
        }
        await newer.site.settle()
        #expect(await newer.site.brandRunningPeak <= SiteIconLoader.prefetchWidth)
        #expect(await newer.site.brandRunningPeak >= 1)
        for host in hosts {
            #expect(newer.site.cachedParentBrand(for: "https://" + host)?.packVersion == 8)
            let homes = StubProtocol.requests(host: host).filter { ["", "/"].contains($0.url?.path) }
            #expect(homes.count == 2, "\(host)")
        }
    }

    /// A host that failed recently, with a parent brand of an older pack: the row's own task gets
    /// the new parent brand, the queued search awaited.
    @Test func failedHostAwaitsTheQueuedSearch() async throws {
        let cache = SiteIconLoaderTests.tempDirectory()
        let host = "members.failed-brand-test.com"
        let url = "https://" + host
        // First pack: the page names no brand and the site has no icon.
        Self.serve(host, html: "<title>Members</title>", favicon: nil)
        let old = try Self.make(version: 7, cache: cache)
        #expect(await old.icon(for: url, title: "") == nil)
        #expect(old.site.cachedParentBrand(for: url)?.byName == nil)
        // The page now names Bay Club and a newer pack arrives: the failure is still fresh.
        Self.serve(host, html: #"<meta property="og:site_name" content="Bay Club Connect">"#, favicon: nil)
        let newer = try Self.make(version: 8, cache: cache)
        #expect(newer.cachedIcon(for: url, title: "") == nil)
        #expect(await newer.icon(for: url, title: "") == Self.bay)
        #expect(newer.cachedIcon(for: url, title: "") == Self.bay)
    }

    /// More such hosts than `prefetchWidth` asked at once: every caller returns, at most four
    /// searches run together.
    @Test func manyWaitingHostsAllReturn() async throws {
        let cache = SiteIconLoaderTests.tempDirectory()
        let hosts = (1...10).map { "gym\($0).waiting-test.com" }
        for host in hosts { Self.serve(host, html: "<title>Members</title>", favicon: nil) }
        let old = try Self.make(version: 7, cache: cache)
        for host in hosts { _ = await old.icon(for: "https://" + host, title: "") }
        for host in hosts {
            Self.serve(host, html: #"<meta property="og:site_name" content="Acme Portal">"#, favicon: nil)
        }
        let newer = try Self.make(version: 8, cache: cache)
        let shown = await withTaskGroup(of: Data?.self) { group in
            for host in hosts + hosts {
                group.addTask { await newer.icon(for: "https://" + host, title: "") }
            }
            var all: [Data?] = []
            for await icon in group { all.append(icon) }
            return all
        }
        #expect(shown.count == 20)
        #expect(shown.allSatisfy { $0 == Self.acme })
        #expect(await newer.site.brandRunningPeak <= SiteIconLoader.prefetchWidth)
        for host in hosts {
            let homes = StubProtocol.requests(host: host).filter { ["", "/"].contains($0.url?.path) }
            // Counted since the second `serve` (which resets the count): one search per host.
            #expect(homes.count == 1, "\(host)")
        }
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
