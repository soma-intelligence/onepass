import Foundation
import OnePassCore

/// Timeline of one item (detail footer): what happened and when, never a value. Items saved before
/// the core recorded events get a synthesized one (creation, previous passwords, last change).
extension VaultSession {
    public func itemTimeline(vaultID: String, itemID: String) async throws -> [FfiTimelineEvent] {
        try await read { try $0.itemTimeline(vaultId: vaultID, itemId: itemID) }
    }
}
