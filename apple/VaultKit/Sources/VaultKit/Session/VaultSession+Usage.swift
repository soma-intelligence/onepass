import Foundation
import OnePassCore

/// How an item was used, from its summary: AutoFill fills and uses inside the app
/// (`VaultSession.noteAppUse`) alike. Synced with the item, never a ranking signal of AutoFill for
/// the uses inside the app.
extension FfiItemSummary {
    /// How many times the item was used (a forgotten site no longer counts).
    public var useCount: Int { Int(uses) }

    /// When the item was last used, nil for never.
    public var lastUsedAt: Date? { lastUseAt.map { Date(timeIntervalSince1970: TimeInterval($0)) } }
}

/// Récemment utilisés and Fréquemment utilisés of the iPhone Home. Both list the active items
/// (neither archived nor trashed) of the visible vaults; the account profile is never a summary.
extension VaultSession {
    /// The items used last, newest first: a use (`lastUsedAt`, synced) or an opening in this
    /// session (`recents`, memory only), whichever is later. At most `limit`.
    public func recentlyUsed(limit: Int = 6) -> [FfiItemSummary] {
        let dated: [(item: FfiItemSummary, at: Date)] = usableSummaries().compactMap { item in
            let at = [item.lastUsedAt, openedAt[item.id]].compactMap { $0 }.max()
            return at.map { (item, $0) }
        }
        return dated
            .sorted { a, b in
                if a.at != b.at { return a.at > b.at }
                return Self.titleFirst(a.item, b.item)
            }
            .prefix(max(limit, 0))
            .map(\.item)
    }

    /// The items used most, most first, then the one used last first. Only items used at least
    /// once (opening one is no use). At most `limit`.
    public func frequentlyUsed(limit: Int = 6) -> [FfiItemSummary] {
        usableSummaries()
            .filter { $0.useCount > 0 }
            .sorted { a, b in
                if a.useCount != b.useCount { return a.useCount > b.useCount }
                let (x, y) = (a.lastUsedAt ?? .distantPast, b.lastUsedAt ?? .distantPast)
                if x != y { return x > y }
                return Self.titleFirst(a, b)
            }
            .prefix(max(limit, 0))
            .map { $0 }
    }

    /// Active items of the visible vaults.
    func usableSummaries() -> [FfiItemSummary] {
        summaries.filter { !$0.archived && $0.trashedAt == nil && !hiddenVaultIDs.contains($0.vaultId) }
    }

    /// A stable order for ties: by title, then by id.
    nonisolated static func titleFirst(_ a: FfiItemSummary, _ b: FfiItemSummary) -> Bool {
        switch a.title.localizedStandardCompare(b.title) {
        case .orderedAscending: true
        case .orderedDescending: false
        case .orderedSame: a.id < b.id
        }
    }
}

extension FfiItemSummary {
    /// This item as the account profile names it.
    var ref: FfiItemRef { FfiItemRef(vaultId: vaultId, itemId: id) }
}
