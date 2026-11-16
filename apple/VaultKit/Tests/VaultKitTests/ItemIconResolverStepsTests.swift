import Foundation
import Testing

@testable import VaultKit

/// The cache-only path (`cachedSource`, a row's first frame and the Debug report) and the async
/// path (`icon(for:)`, a row's task) pick the same step of the order, for each of the seven steps.
@Suite struct ItemIconResolverStepsTests {
    struct Case: Sendable, CustomTestStringConvertible {
        let name: String
        let url: String?
        let title: String
        let chosen: Data?
        let source: IconSource
        /// The icon the step gives; nil: any non-nil icon (a site icon, re-encoded by the loader).
        let data: Data?
        var testDescription: String { name }
    }

    static let chosen = Data("chosen-steps".utf8)
    static let platform = SiteIconLoaderTests.patternPNG(seed: 41)

    static let cases: [Case] = [
        Case(name: "1 chosen", url: "https://www.brandclub.com/signin", title: "Brand club", chosen: chosen,
            source: .chosen, data: chosen),
        Case(name: "2 pack by host", url: "https://www.brandclub.com/signin", title: "", chosen: nil,
            source: .pack, data: ItemIconResolverParentBrandTests.brand),
        Case(name: "3 pack by title", url: nil, title: "Acme", chosen: nil,
            source: .pack, data: ItemIconResolverParentBrandTests.acme),
        Case(name: "4 parent brand by name", url: "https://members.bayclub-steps-test.com/login", title: "",
            chosen: nil, source: .parentBrand, data: ItemIconResolverParentBrandTests.bay),
        Case(name: "5 site icon", url: "https://own-steps-test.com/", title: "", chosen: nil,
            source: .site, data: nil),
        Case(name: "6 parent brand by link", url: "https://brandclub-portal-steps-test.com/signin", title: "",
            chosen: nil, source: .parentBrand, data: ItemIconResolverParentBrandTests.brand),
        Case(name: "7 monogram", url: "https://nothing-steps-test.com/", title: "", chosen: nil,
            source: .monogram, data: nil),
    ]

    static func serveAll() {
        ItemIconResolverParentBrandTests.serve(
            "members.bayclub-steps-test.com",
            html: #"<title>Welcome</title><meta property="og:site_name" content="Bay Club Connect">"#,
            favicon: SiteIconLoaderTests.patternPNG(seed: 42))
        ItemIconResolverParentBrandTests.serve(
            "own-steps-test.com", html: "<title>Own</title>", favicon: SiteIconLoaderTests.patternPNG(seed: 43))
        ItemIconResolverParentBrandTests.serve(
            "brandclub-portal-steps-test.com",
            html: #"<title>Members</title><a href="https://brandclub.com/">home</a>"#, favicon: platform)
        ItemIconResolverParentBrandTests.serve("nothing-steps-test.com", html: "<title>Members</title>", favicon: nil)
    }

    @Test(arguments: cases) func bothPathsPickTheSameStep(_ step: Case) async throws {
        Self.serveAll()
        let reject = String(format: "%016llx", try SiteIconLoaderTests.rejectHash(Self.platform))
        let resolver = try ItemIconResolverParentBrandTests.make(rejects: [reject])
        let fetched = await resolver.icon(for: step.url, title: step.title, chosen: step.chosen)
        let cached = resolver.cachedSource(for: step.url, title: step.title, chosen: step.chosen)
        #expect(cached.source == step.source)
        #expect(cached.data == fetched)
        if let data = step.data {
            #expect(fetched == data)
        } else {
            #expect((fetched != nil) == (step.source == .site))
        }
    }
}
