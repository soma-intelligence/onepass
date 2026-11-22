import Foundation
import OSLog
import OnePassCore

/// What saving a chip read needs from the vault. `VaultSession` is the app's; tests wrap it to
/// make one step fail.
@MainActor
public protocol ChipItemStore: AnyObject {
    func save(_ item: FfiItem) async throws -> FfiItem
    func addAttachment(itemID: String, vaultID: String, name: String, mime: String, data: Data) async throws
        -> FfiItem
    func removeAttachment(itemID: String, vaultID: String, attachmentID: String) async throws -> FfiItem
    /// The item as stored now, with no side effect on recents.
    func storedItem(vaultID: String, itemID: String) async throws -> FfiItem
    func mergeChip(item: FfiItem, read chip: FfiChipRead, takeScanned: Set<String>) async throws -> FfiChipMerge
}

extension VaultSession: ChipItemStore {}

/// Saves a passport made from a chip read in three steps, resumable after a failure: the item,
/// then the portrait attached and linked from the `portrait` field, then the previous portrait
/// removed (a later read). Each step that succeeded is kept: "Enregistrer" again resumes from the
/// stored item instead of the stale one of the reveal. A portrait attached but not linked is
/// removed again (on the next call if that removal fails too), so no orphan file stays. Once the
/// item is stored (`stored`), the choices of the reveal (vault, conflicts) are fixed: the flow
/// locks them.
@MainActor
public final class ChipPassportSaver {
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "scan")

    /// The portrait's attachment name.
    public static let portraitName = "portrait.jpg"

    private let store: any ChipItemStore
    /// The item as stored by the first step, then after each later step.
    public private(set) var stored: FfiItem?
    private var linked = false
    /// A portrait attached by a failed link whose removal failed too: removed on the next call.
    private var orphanID: String?
    /// The portrait the item pointed to before this read (a later read replaces it).
    private var previousPortraitID: String?

    public init(store: any ChipItemStore) {
        self.store = store
    }

    /// The attachment the `portrait` field points to.
    public static func portraitID(of item: FfiItem) -> String? {
        for field in item.sections.lazy.flatMap(\.fields) where field.id == "portrait" {
            if case .file(let attachment) = field.value { return attachment.id }
        }
        return nil
    }

    static func setField(_ id: String, to value: FfiFieldValue, in item: inout FfiItem) {
        for s in item.sections.indices {
            for f in item.sections[s].fields.indices where item.sections[s].fields[f].id == id {
                item.sections[s].fields[f].value = value
                return
            }
        }
    }

    /// Saves `item` (a new passport from the chip, or the merge shown in the reveal) and its
    /// portrait (JPEG). `rescan`: a later read of a stored passport; the item is then merged again
    /// into the stored one at save time, so edits synced since the merge are kept, and
    /// `takeScanned` (field ids) are the conflicts the user settled for the chip. The core applies
    /// them where the values still differ, and keeps the chip badge only when no conflict keeps
    /// the stored value.
    public func save(
        _ item: FfiItem, rescan: FfiChipRead? = nil, takeScanned: Set<String> = [], portrait: Data?
    ) async throws -> FfiItem {
        var current: FfiItem
        if let stored {
            current = stored
        } else {
            var toSave = item
            if let rescan {
                let latest = try await store.storedItem(vaultID: item.vaultId, itemID: item.id)
                toSave = try await store.mergeChip(item: latest, read: rescan, takeScanned: takeScanned).item
            }
            previousPortraitID = Self.portraitID(of: toSave)
            current = try await store.save(toSave)
            stored = current
        }
        if let orphan = orphanID {
            if current.attachments.contains(where: { $0.id == orphan }) {
                current = try await store.removeAttachment(
                    itemID: current.id, vaultID: current.vaultId, attachmentID: orphan)
                stored = current
            }
            orphanID = nil
        }
        if let portrait, !linked {
            current = try await link(portrait, to: current)
            linked = true
            stored = current
        }
        if linked, let old = previousPortraitID, old != Self.portraitID(of: current),
            current.attachments.contains(where: { $0.id == old })
        {
            current = try await store.removeAttachment(itemID: current.id, vaultID: current.vaultId, attachmentID: old)
            stored = current
        }
        previousPortraitID = linked ? nil : previousPortraitID
        return current
    }

    /// Attaches the portrait and points the `portrait` field at it. If the link fails, the new
    /// file is removed again.
    private func link(_ portrait: Data, to item: FfiItem) async throws -> FfiItem {
        // The files as stored right now: the new one is the file `addAttachment` adds to these.
        let before = try await store.storedItem(vaultID: item.vaultId, itemID: item.id)
        let withFile = try await store.addAttachment(
            itemID: item.id, vaultID: item.vaultId, name: Self.portraitName, mime: "image/jpeg", data: portrait)
        let known = Set(before.attachments.map(\.id))
        guard let added = withFile.attachments.first(where: { !known.contains($0.id) }) else {
            return withFile
        }
        var linkedItem = withFile
        Self.setField("portrait", to: .file(value: added), in: &linkedItem)
        do {
            return try await store.save(linkedItem)
        } catch {
            Self.log.error("scan: portrait link failed, removing the new attachment")
            if let cleaned = try? await store.removeAttachment(
                itemID: withFile.id, vaultID: withFile.vaultId, attachmentID: added.id)
            {
                stored = cleaned
            } else {
                Self.log.error("scan: new attachment not removed, retried on the next save")
                stored = withFile
                orphanID = added.id
            }
            throw error
        }
    }
}
