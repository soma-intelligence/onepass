import Foundation

/// Sidebar filters. Every filter except `archive` and `trash` leaves out archived and trashed items.
public enum ItemFilter: Hashable, Sendable {
    case all, favorites
    case vault(String)
    case category(FfiItemType)
    case tag(String)
    case archive, trash

    public func matches(_ item: FfiItemSummary) -> Bool {
        let active = !item.archived && item.trashedAt == nil
        switch self {
        case .all: return active
        case .favorites: return active && item.favorite
        case .vault(let id): return active && item.vaultId == id
        case .category(let type): return active && item.itemType == type
        case .tag(let tag): return active && item.tags.contains(tag)
        case .archive: return item.archived && item.trashedAt == nil
        case .trash: return item.trashedAt != nil
        }
    }
}

public enum ItemSort: Hashable, Sendable {
    /// Title, Finder order (case and accent insensitive, numbers by value).
    case title
    /// Most recently modified first.
    case updated

    public func sorted(_ items: [FfiItemSummary]) -> [FfiItemSummary] {
        items.sorted { a, b in
            switch self {
            case .title:
                let order = a.title.localizedStandardCompare(b.title)
                return order == .orderedSame ? a.id < b.id : order == .orderedAscending
            case .updated:
                return a.updatedAt == b.updatedAt ? a.id < b.id : a.updatedAt > b.updatedAt
            }
        }
    }
}

/// Sidebar badges. Vault, type, tag and favorite counts cover active items only.
public struct ItemCounts: Equatable, Sendable {
    public var all = 0
    public var favorites = 0
    public var archive = 0
    public var trash = 0
    public var byVault: [String: Int] = [:]
    public var byType: [FfiItemType: Int] = [:]
    public var byTag: [String: Int] = [:]

    public init() {}

    public init(_ items: [FfiItemSummary]) {
        for item in items {
            if ItemFilter.trash.matches(item) {
                trash += 1
            } else if ItemFilter.archive.matches(item) {
                archive += 1
            } else {
                all += 1
                if item.favorite { favorites += 1 }
                byVault[item.vaultId, default: 0] += 1
                byType[item.itemType, default: 0] += 1
                for tag in Set(item.tags) { byTag[tag, default: 0] += 1 }
            }
        }
    }
}
