import Foundation

/// One row of the report: a comparison, or a pair that could not be compared.
public struct ReportEntry: Sendable {
    public enum Outcome: Sendable {
        case compared(ComparisonResult, reference: RGBAImage, candidate: RGBAImage)
        /// A reference without a screenshot, a screenshot without a reference, or an unreadable file.
        case problem(String)
    }

    public var name: String
    public var outcome: Outcome

    public init(name: String, outcome: Outcome) {
        self.name = name
        self.outcome = outcome
    }

    public var passed: Bool {
        if case .compared(let r, _, _) = outcome { return r.passed }
        return false
    }
}

/// Machine-readable summary written next to the HTML (`report.json`).
public struct ReportSummary: Codable, Sendable, Equatable {
    public struct Row: Codable, Sendable, Equatable {
        public var name: String
        public var passed: Bool
        public var ssim: Double?
        public var ssimAtZeroOffset: Double?
        public var offsetPx: OffsetSearch.Offset?
        public var offsetPt: Double?
        public var changedPixelRatio: Double?
        public var ssimThreshold: Double?
        public var maxOffsetPt: Double?
        public var problems: [String]
    }

    public var passed: Int
    public var failed: Int
    public var rows: [Row]
}

public enum HTMLReport {
    /// Writes `index.html`, `report.json` and `images/` into `directory`. Returns the summary.
    @discardableResult
    public static func write(_ entries: [ReportEntry], title: String = "DesignBridge visual diff", to directory: URL) throws -> ReportSummary {
        let fm = FileManager.default
        let images = directory.appendingPathComponent("images", isDirectory: true)
        try fm.createDirectory(at: images, withIntermediateDirectories: true)

        var rows: [ReportSummary.Row] = []
        var cards: [String] = []
        var usedSlugs: Set<String> = []

        for entry in entries {
            var slug = slugify(entry.name)
            var n = 2
            while usedSlugs.contains(slug) { slug = "\(slugify(entry.name))-\(n)"; n += 1 }
            usedSlugs.insert(slug)

            switch entry.outcome {
            case .compared(let r, let reference, let candidate):
                try reference.writePNG(to: images.appendingPathComponent("\(slug)-reference.png"))
                try candidate.writePNG(to: images.appendingPathComponent("\(slug)-candidate.png"))
                try r.diffImage.writePNG(to: images.appendingPathComponent("\(slug)-diff.png"))
                rows.append(.init(
                    name: entry.name, passed: r.passed, ssim: r.ssim, ssimAtZeroOffset: r.ssimAtZeroOffset,
                    offsetPx: r.offset, offsetPt: r.offsetPoints, changedPixelRatio: r.changedPixelRatio,
                    ssimThreshold: r.thresholds.ssimThreshold, maxOffsetPt: r.thresholds.maxOffsetPoints,
                    problems: r.failures
                ))
                cards.append(card(entry.name, slug: slug, result: r))
            case .problem(let message):
                rows.append(.init(name: entry.name, passed: false, problems: [message]))
                cards.append("""
                <section class="card fail" id="\(slug)">
                  <header><h2>\(escape(entry.name))</h2><span class="badge">error</span></header>
                  <p class="problem">\(escape(message))</p>
                </section>
                """)
            }
        }

        let passed = rows.filter(\.passed).count
        let summary = ReportSummary(passed: passed, failed: rows.count - passed, rows: rows)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(summary).write(to: directory.appendingPathComponent("report.json"), options: .atomic)
        try page(title: title, summary: summary, cards: cards)
            .write(to: directory.appendingPathComponent("index.html"), atomically: true, encoding: .utf8)
        return summary
    }

    static func card(_ name: String, slug: String, result r: ComparisonResult) -> String {
        let status = r.passed ? "pass" : "fail"
        let ssim = String(format: "%.4f", r.ssim)
        let zero = String(format: "%.4f", r.ssimAtZeroOffset)
        let threshold = String(format: "%.2f", r.thresholds.ssimThreshold)
        let offset = String(format: "%.2f", r.offsetPoints)
        let maxOffset = String(format: "%.2f", r.thresholds.maxOffsetPoints)
        let changed = String(format: "%.2f%%", r.changedPixelRatio * 100)
        let problems = r.failures.map { "<li>\(escape($0))</li>" }.joined()
        let resized = r.candidateWasResized ? "<li>candidate resampled to the reference size</li>" : ""
        return """
        <section class="card \(status)" id="\(slug)">
          <header><h2>\(escape(name))</h2><span class="badge">\(status)</span></header>
          <dl>
            <div><dt>SSIM</dt><dd>\(ssim) <small>min \(threshold), \(zero) unshifted</small></dd></div>
            <div><dt>Offset</dt><dd>\(offset) pt <small>(\(r.offset.dx), \(r.offset.dy)) px, max \(maxOffset) pt</small></dd></div>
            <div><dt>Changed</dt><dd>\(changed) <small>of pixels</small></dd></div>
          </dl>
          <ul class="problems">\(problems)\(resized)</ul>
          <div class="panels">
            <figure><img loading="lazy" src="images/\(slug)-reference.png" alt="Reference (Penpot)"><figcaption>Penpot</figcaption></figure>
            <figure><img loading="lazy" src="images/\(slug)-candidate.png" alt="Candidate (app)"><figcaption>App</figcaption></figure>
            <figure><img loading="lazy" src="images/\(slug)-diff.png" alt="Difference"><figcaption>Diff</figcaption></figure>
          </div>
        </section>
        """
    }

    static func page(title: String, summary: ReportSummary, cards: [String]) -> String {
        """
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>\(escape(title))</title>
        <style>
        :root { --bg: #f6f6f7; --card: #fff; --text: #111; --muted: #666; --line: #e3e3e6; --pass: #1a7f37; --fail: #c62828; }
        @media (prefers-color-scheme: dark) {
          :root { --bg: #0e0e10; --card: #18181b; --text: #f2f2f3; --muted: #a0a0a8; --line: #2a2a30; --pass: #4ac26b; --fail: #ff6b6b; }
        }
        * { box-sizing: border-box; }
        body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--text); font: 15px/1.45 -apple-system, system-ui, sans-serif; }
        main { max-width: 1280px; margin: 0 auto; }
        h1 { font-size: 22px; margin: 0 0 4px; }
        .summary { color: var(--muted); margin: 0 0 24px; }
        .card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin-bottom: 16px; }
        .card header { display: flex; align-items: center; gap: 12px; }
        .card h2 { font-size: 17px; margin: 0; overflow-wrap: anywhere; }
        .badge { font-size: 12px; font-weight: 600; text-transform: uppercase; padding: 2px 8px; border-radius: 999px; color: #fff; }
        .pass .badge { background: var(--pass); }
        .fail .badge { background: var(--fail); }
        dl { display: flex; flex-wrap: wrap; gap: 8px 24px; margin: 12px 0; }
        dt { color: var(--muted); font-size: 12px; }
        dd { margin: 0; font-variant-numeric: tabular-nums; }
        small { color: var(--muted); }
        .problems { margin: 0 0 12px; padding-left: 18px; color: var(--fail); }
        .problem { color: var(--fail); }
        .panels { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
        figure { margin: 0; }
        figure img { width: 100%; height: auto; border: 1px solid var(--line); border-radius: 8px; background: #fff; }
        figcaption { color: var(--muted); font-size: 12px; text-align: center; margin-top: 4px; }
        @media (max-width: 640px) { .panels { grid-template-columns: 1fr; } }
        </style>
        </head>
        <body>
        <main>
        <h1>\(escape(title))</h1>
        <p class="summary">\(summary.passed) passed, \(summary.failed) failed, \(summary.rows.count) total</p>
        \(cards.joined(separator: "\n"))
        </main>
        </body>
        </html>
        """
    }

    public static func escape(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for ch in s {
            switch ch {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&#39;"
            default: out.append(ch)
            }
        }
        return out
    }

    public static func slugify(_ s: String) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        var out = ""
        var lastDash = false
        for ch in s.lowercased() {
            if allowed.contains(ch) {
                out.append(ch)
                lastDash = false
            } else if !lastDash {
                out.append("-")
                lastDash = true
            }
        }
        let trimmed = out.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return trimmed.isEmpty ? "image" : trimmed
    }
}
