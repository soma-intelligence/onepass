import AppIntents
import Foundation

/// An item for Shortcuts and Siri: its references and what the picker shows, never a secret.
/// Identifier: `"<vault>:<item>"`.
struct ItemEntity: AppEntity {
    static let typeDisplayRepresentation: TypeDisplayRepresentation = "Élément"
    static let defaultQuery = ItemEntityQuery()

    let id: String
    let title: String
    let subtitle: String

    init(vaultID: String, itemID: String, title: String, subtitle: String) {
        id = "\(vaultID):\(itemID)"
        self.title = title
        self.subtitle = subtitle
    }

    var displayRepresentation: DisplayRepresentation {
        subtitle.isEmpty
            ? DisplayRepresentation(title: "\(title)")
            : DisplayRepresentation(title: "\(title)", subtitle: "\(subtitle)")
    }

    /// The item behind the identifier, nil when it is not `"<vault>:<item>"`.
    var ref: ItemRef? { Self.ref(from: id) }

    static func ref(from id: String) -> ItemRef? {
        let parts = id.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
        return ItemRef(vaultID: String(parts[0]), itemID: String(parts[1]))
    }
}

/// Unlocked: the session's items. Locked: the widget favorites on iPhone and iPad, else nothing
/// with "Déverrouille OnePass pour choisir un élément".
struct ItemEntityQuery: EntityStringQuery {
    func entities(for identifiers: [ItemEntity.ID]) async throws -> [ItemEntity] {
        let (known, unlocked) = await MainActor.run { (IntentBridge.entities(), IntentBridge.unlocked) }
        return identifiers.compactMap { id in
            if let entity = known.first(where: { $0.id == id }) { return entity }
            // Locked: an item picked earlier still resolves; the app checks it after the unlock.
            guard !unlocked, let ref = ItemEntity.ref(from: id) else { return nil }
            return ItemEntity(
                vaultID: ref.vaultID, itemID: ref.itemID, title: String(localized: "Élément"), subtitle: "")
        }
    }

    func entities(matching string: String) async throws -> [ItemEntity] {
        try await suggestedEntities().filter { $0.title.localizedStandardContains(string) }
    }

    func suggestedEntities() async throws -> [ItemEntity] {
        let (entities, unlocked) = await MainActor.run { (IntentBridge.entities(), IntentBridge.unlocked) }
        if entities.isEmpty, !unlocked { throw IntentError.locked }
        return entities.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
    }
}
