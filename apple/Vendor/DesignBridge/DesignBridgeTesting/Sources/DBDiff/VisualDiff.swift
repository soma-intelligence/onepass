import Foundation

/// The library entry point behind `dbdiff`: compare files or folders and write the report.
public enum VisualDiff {
    /// Compares `reference` against `candidate` (two files, or two folders paired by name) and
    /// writes the HTML report into `output`. `base` carries options the caller set explicitly;
    /// `config` thresholds apply on top of the defaults, then per-name overrides.
    public static func run(
        reference: URL,
        candidate: URL,
        output: URL,
        config: ParityConfig = .init(),
        base: ComparisonOptions = .init(),
        explicit: ExplicitOptions = .init()
    ) throws -> ReportSummary {
        let pairs: [Pairing.Pair]
        if isDirectory(reference) != isDirectory(candidate) {
            throw DBDiffError.io("reference and candidate must both be files or both be folders")
        }
        if isDirectory(reference) {
            pairs = Pairing.pairs(
                references: try Pairing.images(in: reference),
                candidates: try Pairing.images(in: candidate)
            )
        } else {
            pairs = [Pairing.Pair(
                name: reference.deletingPathExtension().lastPathComponent,
                reference: reference,
                candidate: candidate
            )]
        }

        var entries: [ReportEntry] = []
        for pair in pairs {
            guard let r = pair.reference else {
                entries.append(.init(name: pair.name, outcome: .problem("no Penpot reference for this screenshot")))
                continue
            }
            guard let c = pair.candidate else {
                entries.append(.init(name: pair.name, outcome: .problem("no app screenshot for this reference")))
                continue
            }
            do {
                var options = try config.options(for: pair.name, base: base)
                explicit.apply(to: &options)
                let refImage = try RGBAImage(contentsOf: r)
                let candImage = try RGBAImage(contentsOf: c)
                let result = try ImageComparator.compare(
                    reference: refImage, candidate: candImage, name: pair.name, options: options
                )
                entries.append(.init(name: pair.name, outcome: .compared(result, reference: refImage, candidate: candImage)))
            } catch {
                entries.append(.init(name: pair.name, outcome: .problem("\(error)")))
            }
        }
        return try HTMLReport.write(entries, to: output)
    }

    /// Command line values win over the config file, so they are applied last.
    public struct ExplicitOptions: Sendable, Equatable {
        public var ssim: Double?
        public var maxOffsetPt: Double?
        public var scale: Double?

        public init(ssim: Double? = nil, maxOffsetPt: Double? = nil, scale: Double? = nil) {
            self.ssim = ssim
            self.maxOffsetPt = maxOffsetPt
            self.scale = scale
        }

        func apply(to o: inout ComparisonOptions) {
            if let ssim { o.ssimThreshold = ssim }
            if let maxOffsetPt { o.maxOffsetPoints = maxOffsetPt }
            if let scale { o.scale = scale }
        }
    }

    static func isDirectory(_ url: URL) -> Bool {
        var dir: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &dir) && dir.boolValue
    }
}
