import Foundation
import Testing

@testable import VaultKit

/// The Debug report of icons to check: one login per source, trash and other types left out.
@Suite struct IconSourceReportTests {
    static let chosenIcon = Data("chosen-icon".utf8)

    static func login(_ title: String, url: String?, icon: String? = nil, trashed: Bool = false, type: FfiItemType = .login)
        -> FfiItemSummary
    {
        var item = summary(title, url: url, type: type, trashedAt: trashed ? 1 : nil)
        item.customIconId = icon
        return item
    }

    @Test func reportsEachSourceSortedAndCopies() async throws {
        let store = CustomIconStore { _ in Self.chosenIcon }
        let base = try ItemIconResolverParentBrandTests.make()
        let resolver = ItemIconResolver(pack: base.pack, site: base.site, custom: store, enabled: { true })
        ItemIconResolverParentBrandTests.serve(
            "members.bayclub-report-test.com",
            html: #"<title>Welcome</title><meta property="og:site_name" content="Bay Club Connect">"#,
            favicon: SiteIconLoaderTests.patternPNG(seed: 21))
        ItemIconResolverParentBrandTests.serve(
            "own-icon-report-test.com", html: "<title>Own</title>", favicon: SiteIconLoaderTests.patternPNG(seed: 22))
        _ = await resolver.icon(for: "https://members.bayclub-report-test.com/login", title: "")
        _ = await resolver.icon(for: "https://own-icon-report-test.com/", title: "")

        // Not loaded before: the report loads it, so it counts as chosen.
        let chosen = Self.login("Mine", url: "https://mine-report-test.com", icon: "ic1")
        let items = [
            chosen,
            Self.login("Brand club", url: "https://www.brandclub.com/signin"),
            Self.login("Gym", url: "https://members.bayclub-report-test.com/login"),
            Self.login("Own", url: "https://own-icon-report-test.com/"),
            Self.login("Unknown", url: "https://unknown-report-test.com/"),
            Self.login("No address", url: nil),
            Self.login("Gone", url: "https://gone-report-test.com", trashed: true),
            Self.login("A note", url: nil, type: .secureNote),
        ]
        let rows = await IconSourceReport.report(items, resolver: resolver)
        #expect(
            rows.map { "\($0.domain)|\($0.title)|\($0.source.rawValue)" } == [
                "|No address|monogram",
                "unknown-report-test.com|Unknown|monogram",
                "own-icon-report-test.com|Own|site",
                "bayclub-report-test.com|Gym|parentBrand",
                "brandclub.com|Brand club|pack",
                "mine-report-test.com|Mine|chosen",
            ])
        #expect(IconSourceReport.text(rows).split(separator: "\n").first == "\tNo address\tmonogram")
    }

    @Test func iconsOffGivesMonogramForEverything() async throws {
        let base = try ItemIconResolverParentBrandTests.make()
        let off = ItemIconResolver(pack: base.pack, site: base.site, enabled: { false })
        let rows = await IconSourceReport.report([Self.login("Brand club", url: "https://brandclub.com")], resolver: off)
        #expect(rows.map(\.source) == [.monogram])
    }
}
