import AppIntents
import Foundation
import GlanceKit
import VaultKit

/// The App Intents run in the app process: they reach the process-wide `AppModel` through this
/// bridge, set by `AppModel.start()` once the first window is up. Weak: the bridge never keeps the
/// model (and its session) alive.
@MainActor
enum IntentBridge {
    static weak var model: AppModel?

    /// The model, waiting a few seconds for a launch started by the intent itself.
    static func awaitModel() async throws -> AppModel {
        for _ in 0..<50 {
            if let model { return model }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw IntentError.unavailable
    }

    /// Items a shortcut can pick. Unlocked: every item that is not in Supprimés récemment, outside
    /// the vaults hidden on this device. Locked (iPhone and iPad): the widget snapshot's favorites,
    /// titles only. Otherwise nothing.
    static func entities() -> [ItemEntity] {
        if let session = model?.session, session.state == .unlocked {
            let hidden = session.hiddenVaultIDs
            return session.summaries
                .filter { $0.trashedAt == nil && !hidden.contains($0.vaultId) }
                .map { ItemEntity(vaultID: $0.vaultId, itemID: $0.id, title: $0.title, subtitle: $0.subtitle) }
        }
        #if os(iOS)
        let favorites = GlanceStore.shared()?.read()?.favorites ?? []
        return favorites.map { ItemEntity(vaultID: $0.vaultID, itemID: $0.itemID, title: $0.title, subtitle: "") }
        #else
        return []
        #endif
    }

    /// Whether the entity list comes from the open session (else: locked, partial or empty).
    static var unlocked: Bool { model?.session.state == .unlocked }
}

/// What an intent reports to Shortcuts or Siri. Never carries vault data.
enum IntentError: Error, CustomLocalizedStringResourceConvertible {
    /// The app did not come up in time to run the intent.
    case unavailable
    /// The picked item is not a valid OnePass item reference.
    case itemNotFound
    /// Locked, and nothing to pick from (spec 9).
    case locked
    /// The core refused the generator recipe.
    case generationFailed

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .unavailable: "OnePass n'a pas pu s'ouvrir"
        case .itemNotFound: "Élément introuvable"
        case .locked: "Déverrouille OnePass pour choisir un élément"
        case .generationFailed: "Le mot de passe n'a pas pu être généré"
        }
    }
}
