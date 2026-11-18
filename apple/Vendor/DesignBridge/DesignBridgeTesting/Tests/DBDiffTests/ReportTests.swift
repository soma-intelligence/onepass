import Foundation
import Testing
@testable import DBDiff

@Suite("Report, config and pairing")
struct ReportTests {
    func tempDir() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("dbdiff-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func htmlReportWritesPanelsAndSummary() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let ref = Fixtures.screen()
        let cand = Fixtures.screen(buttonColor: RGBA(230, 40, 40))
        let r = try ImageComparator.compare(reference: ref, candidate: cand, name: "RX/Menu <row>", options: .init(ssimThreshold: 0.999))
        let summary = try HTMLReport.write([
            ReportEntry(name: "RX/Menu <row>", outcome: .compared(r, reference: ref, candidate: cand)),
            ReportEntry(name: "Orphan", outcome: .problem("no app screenshot for this reference")),
        ], to: dir)

        #expect(summary.passed == 0)
        #expect(summary.failed == 2)
        let html = try String(contentsOf: dir.appendingPathComponent("index.html"), encoding: .utf8)
        #expect(html.contains("RX/Menu &lt;row&gt;"))
        #expect(!html.contains("<row>"))
        #expect(html.contains("images/rx-menu-row-reference.png"))
        #expect(html.contains("images/rx-menu-row-candidate.png"))
        #expect(html.contains("images/rx-menu-row-diff.png"))
        #expect(html.contains("no app screenshot for this reference"))
        for kind in ["reference", "candidate", "diff"] {
            #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("images/rx-menu-row-\(kind).png").path))
        }
        let json = try JSONDecoder().decode(ReportSummary.self, from: Data(contentsOf: dir.appendingPathComponent("report.json")))
        #expect(json == summary)
    }

    @Test func slugsStayUniqueAndSafe() {
        #expect(HTMLReport.slugify("RX/Menu row") == "rx-menu-row")
        #expect(HTMLReport.slugify("///") == "image")
        #expect(HTMLReport.escape("a&b\"c'") == "a&amp;b&quot;c&#39;")
    }

    @Test func parityConfigLayersDefaultsFileAndOverrides() throws {
        let json = #"""
        {"ssim": 0.95, "maxOffsetPt": 2, "masks": [[0, 0, 402, 54]],
         "overrides": {"Settings": {"ssim": 0.9, "masks": [[0, 800, 402, 74]]}}}
        """#
        let config = try ParityConfig.decode(Data(json.utf8))
        let general = try config.options(for: "Home")
        #expect(general.ssimThreshold == 0.95)
        #expect(general.maxOffsetPoints == 2)
        #expect(general.masks.count == 1)
        let settings = try config.options(for: "Settings")
        #expect(settings.ssimThreshold == 0.9)
        #expect(settings.maxOffsetPoints == 2)
        #expect(settings.masks.count == 2)
    }

    @Test func parityConfigReadsDesignBridgeJSON() throws {
        let json = #"{"penpot": {"file": "OnePass RX"}, "parity": {"ssim": 0.97, "maxOffsetPt": 1}}"#
        let config = try ParityConfig.decode(Data(json.utf8))
        #expect(config.ssim == 0.97)
        #expect(config.maxOffsetPt == 1)
    }

    @Test func badMaskIsRejected() throws {
        let config = ParityConfig(masks: [[1, 2, 3]])
        #expect(throws: DBDiffError.self) { try config.options(for: "x") }
    }

    @Test func pairingMatchesScaleSuffixAndCase() {
        let refs = [URL(fileURLWithPath: "/p/Settings@3x.png"), URL(fileURLWithPath: "/p/Home@3x.png")]
        let cands = [URL(fileURLWithPath: "/a/settings.png"), URL(fileURLWithPath: "/a/Extra.png")]
        let pairs = Pairing.pairs(references: refs, candidates: cands)
        #expect(pairs.map(\.name) == ["Extra", "Home", "Settings"])
        #expect(pairs[0].reference == nil && pairs[0].candidate != nil)
        #expect(pairs[1].reference != nil && pairs[1].candidate == nil)
        #expect(pairs[2].reference != nil && pairs[2].candidate != nil)
    }

    @Test func visualDiffRunsOnFolders() throws {
        let root = try tempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let refDir = root.appendingPathComponent("penpot"), candDir = root.appendingPathComponent("app")
        try FileManager.default.createDirectory(at: refDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: candDir, withIntermediateDirectories: true)
        try Fixtures.screen().writePNG(to: refDir.appendingPathComponent("Home@3x.png"))
        try Fixtures.screen(shift: (1, 0)).writePNG(to: candDir.appendingPathComponent("home.png"))
        try Fixtures.screen().writePNG(to: refDir.appendingPathComponent("Card@3x.png"))
        try Fixtures.screen(buttonColor: RGBA(230, 40, 40)).writePNG(to: candDir.appendingPathComponent("card.png"))

        let out = root.appendingPathComponent("report")
        let summary = try VisualDiff.run(
            reference: refDir, candidate: candDir, output: out,
            explicit: .init(ssim: 0.995)
        )
        #expect(summary.rows.count == 2)
        let home = try #require(summary.rows.first { $0.name == "Home" })
        #expect(home.passed)
        #expect(home.offsetPx == .init(dx: 1, dy: 0))
        let card = try #require(summary.rows.first { $0.name == "Card" })
        #expect(!card.passed)
        #expect(FileManager.default.fileExists(atPath: out.appendingPathComponent("index.html").path))
    }

    @Test func visualDiffRejectsFileAgainstFolder() throws {
        let root = try tempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("a.png")
        try Fixtures.screen().writePNG(to: file)
        #expect(throws: DBDiffError.self) {
            try VisualDiff.run(reference: file, candidate: root, output: root.appendingPathComponent("r"))
        }
    }
}
