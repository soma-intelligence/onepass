import Foundation
import OnePassCore

/// A passport chip read turned into an item (NFC documents P1, spec 6.1 and 6.2). Neither call
/// stores anything: the scan screen saves with `save`, then attaches the portrait.
extension VaultSession {
    /// A new passport item in this vault, filled from the chip.
    public func itemFromChip(vaultID: String, read chip: FfiChipRead) async throws -> FfiItem {
        try await read { try $0.itemFromChip(vaultId: vaultID, read: chip) }
    }

    /// The item as stored now. Unlike `loadItem`, not counted as an opening (recents).
    public func storedItem(vaultID: String, itemID: String) async throws -> FfiItem {
        try await read { try $0.item(vaultId: vaultID, itemId: itemID) }
    }

    /// A later read merged into a passport: blank fields filled, the user's own values kept and
    /// reported as conflicts, the chip section refreshed. `takeScanned`: the conflicts (field ids)
    /// settled for the chip, which take its value. While a conflict keeps the user's value, the
    /// chip status is cleared (no badge over data the chip did not give).
    public func mergeChip(item: FfiItem, read chip: FfiChipRead, takeScanned: Set<String> = []) async throws
        -> FfiChipMerge
    {
        try await read { try $0.mergeChip(item: item, read: chip, takeScanned: takeScanned.sorted()) }
    }
}
