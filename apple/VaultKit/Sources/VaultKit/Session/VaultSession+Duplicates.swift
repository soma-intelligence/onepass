import Foundation
import OnePassCore

/// Possible duplicates (spec 2026-11-03-duplicates): the core finds the groups (strong signals
/// only, never password reuse), plans and runs the merge, and refuses any write to a copy in a
/// shared vault where this account is Read only. Hidden vaults are left out, as in Watchtower.
extension VaultSession {
    /// The groups of possible duplicates of the visible vaults, the suggested primary first in each.
    public func duplicateGroups() async throws -> [FfiDuplicateGroup] {
        let hidden = hiddenVaultIDs.sorted()
        return try await read { try $0.duplicateGroups(excludedVaultIds: hidden) }
    }

    /// What merging `others` into `primary` would save. Writes nothing.
    public func duplicateMergePreview(primary: FfiItemKey, others: [FfiItemKey]) async throws -> FfiMergePreview {
        try await read { try $0.mergeDuplicatesPreview(primary: primary, others: others) }
    }

    /// Merges `others` into `primary`; the others are archived with "Fusionné dans <titre>" in the
    /// app's language. Returns the primary as saved.
    @discardableResult
    public func mergeDuplicates(primary: FfiItemKey, others: [FfiItemKey], primaryTitle: String) async throws -> FfiItem {
        let note = String(
            localized: "duplicates.mergedInto \(primaryTitle)", bundle: VaultKitStrings.bundle)
        return try await write { try $0.mergeDuplicates(primary: primary, others: others, note: note) }
    }

    /// Archives the extra copies.
    public func archiveDuplicates(_ items: [FfiItemKey]) async throws {
        try await write { try $0.archiveDuplicates(items: items) }
    }

    /// Puts the extra copies in Supprimés récemment (restorable).
    public func trashDuplicates(_ items: [FfiItemKey]) async throws {
        try await write { try $0.trashDuplicates(items: items) }
    }

    /// "Pas des doublons": remembered on the items, synced with them.
    public func dismissDuplicates(_ members: [FfiItemKey]) async throws {
        try await write { try $0.dismissDuplicates(members: members) }
    }
}

extension FfiDuplicateCopy {
    /// The copy's vault and id, as the duplicate calls take them.
    public var key: FfiItemKey { FfiItemKey(vaultId: summary.vaultId, itemId: summary.id) }
}

/// The home banner's rule: shown while at least one group was not there when the user closed it.
/// The closed set is kept as the group ids (a hash of the items' ids, nothing else).
public struct DuplicateBannerRule: Sendable, Equatable {
    public var closed: Set<String>

    public init(closed: Set<String> = []) { self.closed = closed }

    /// The groups the banner counts: zero hides it.
    public func visibleCount(of groups: [String]) -> Int {
        let current = Set(groups)
        guard !current.isSubset(of: closed) else { return 0 }
        return current.count
    }

    /// Closing remembers every group on screen; a new group brings the banner back.
    public mutating func close(_ groups: [String]) { closed = Set(groups) }

    /// Storage form: the ids joined by commas.
    public var stored: String { closed.sorted().joined(separator: ",") }

    public init(stored: String) {
        closed = Set(stored.split(separator: ",").map(String.init).filter { !$0.isEmpty })
    }
}
