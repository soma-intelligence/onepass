import Foundation

/// Which step of the resolver's order gave an item its icon (`ItemIconResolver`).
public enum IconSource: String, CaseIterable, Sendable {
    case chosen, pack, parentBrand, site, monogram

    /// The order of the report: the doubtful ones first (monogram, then site, parent brand, pack, chosen).
    var reportRank: Int {
        switch self {
        case .monogram: 0
        case .site: 1
        case .parentBrand: 2
        case .pack: 3
        case .chosen: 4
        }
    }
}

/// The list behind Debug > "Icônes à vérifier": every login with the source of its icon, so a
/// wrong logo can be flagged. Reads the caches only (no request) and sends nothing anywhere.
public enum IconSourceReport {
    public typealias Row = (domain: String, title: String, source: IconSource)

    /// One row per login that is not in the trash, from summaries already loaded. The domain is the
    /// registrable one of the item's address, empty when it has none. Sorted by source (monogram
    /// first), then domain, then title.
    public static func report(_ summaries: [FfiItemSummary], resolver: ItemIconResolver) -> [Row] {
        summaries
            .filter { $0.itemType == .login && $0.trashedAt == nil }
            .map { summary -> Row in
                let source = resolver.cachedSource(
                    for: summary.primaryUrl, title: summary.title, custom: CustomIconKey(summary)
                ).source
                return (ItemIconResolver.registrableDomain(summary.primaryUrl) ?? "", summary.title, source)
            }
            .sorted {
                if $0.source.reportRank != $1.source.reportRank { return $0.source.reportRank < $1.source.reportRank }
                if $0.domain != $1.domain { return $0.domain < $1.domain }
                return $0.title < $1.title
            }
    }

    /// The clipboard text: one line per row, `domain<TAB>title<TAB>source`.
    public static func text(_ rows: [Row]) -> String {
        rows.map { "\($0.domain)\t\($0.title)\t\($0.source.rawValue)" }.joined(separator: "\n")
    }
}
