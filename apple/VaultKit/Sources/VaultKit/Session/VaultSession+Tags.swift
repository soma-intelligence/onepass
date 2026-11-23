import Foundation
import OnePassCore

/// Tags have no store of their own: a tag exists while an item carries it. Deleting a tag takes it
/// off every item that has it (archived and trashed ones too), and leaves the items themselves.
extension VaultSession {
    /// What `removeTags` did: how many items lost a tag, and how many could not be written (an
    /// item in a shared vault this account may only read keeps its tags).
    public struct TagRemoval: Sendable, Equatable {
        public var updated: Int
        public var failed: Int

        public init(updated: Int, failed: Int) {
            self.updated = updated
            self.failed = failed
        }
    }

    /// Takes `tags` off every item of every vault, in one write (one snapshot reload, one sync).
    @discardableResult
    public func removeTags(_ tags: Set<String>) async throws -> TagRemoval {
        let targets = summaries
            .filter { !tags.isDisjoint(with: $0.tags) }
            .map { (vaultID: $0.vaultId, itemID: $0.id) }
        guard !targets.isEmpty else { return TagRemoval(updated: 0, failed: 0) }
        return try await write { core in
            var result = TagRemoval(updated: 0, failed: 0)
            for target in targets {
                do {
                    var item = try core.item(vaultId: target.vaultID, itemId: target.itemID)
                    item.tags.removeAll { tags.contains($0) }
                    _ = try core.saveItem(item: item)
                    result.updated += 1
                } catch {
                    result.failed += 1
                }
            }
            return result
        }
    }
}
