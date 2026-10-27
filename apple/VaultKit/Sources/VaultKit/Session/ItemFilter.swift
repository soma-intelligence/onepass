import Foundation

/// Sidebar filters. Every filter except `archive` and `trash` leaves out archived and trashed items.
/// `nearby` ("À proximité") needs the user's position: `matches` only keeps active items, the list
/// comes from `VaultSession.nearbyItems(from:within:)`.
public enum ItemFilter: Hashable, Sendable {
    case all, favorites
    case nearby
    case vault(String)
    case category(FfiItemType)
    case tag(String)
    case archive, trash

    public func matches(_ item: FfiItemSummary) -> Bool {
        let active = !item.archived && item.trashedAt == nil
        switch self {
        case .all, .nearby: return active
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

/// Why a list shows no row: a search that matches nothing, or a scope that holds nothing yet.
/// Only an active query is "no match"; an empty vault is never shown as a failed search.
public enum EmptyListReason: Equatable, Sendable {
    case noMatch
    case emptyLibrary
    case emptyCategory
    case emptyTag
    case noFavorites
    /// "À proximité": no item with a place around the user.
    case noNearby
    case emptyArchive
    case emptyTrash

    public init(filter: ItemFilter, query: String) {
        if !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            self = .noMatch
            return
        }
        switch filter {
        case .all, .vault: self = .emptyLibrary
        case .category: self = .emptyCategory
        case .tag: self = .emptyTag
        case .favorites: self = .noFavorites
        case .nearby: self = .noNearby
        case .archive: self = .emptyArchive
        case .trash: self = .emptyTrash
        }
    }

    /// The "Nouvel élément" button belongs to the empty state of a scope items can be created in.
    public var offersNewItem: Bool { self == .emptyLibrary || self == .emptyCategory }
}
