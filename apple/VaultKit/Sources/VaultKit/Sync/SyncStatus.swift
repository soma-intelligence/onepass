import Foundation

/// What the settings screen and the sidebar badge show about sync.
public enum SyncStatus: Equatable, Sendable {
    /// No remote (unsigned build, tests).
    case disabled
    case idle(lastSync: Date?)
    case syncing
    case offline
    /// French message for the UI.
    case error(String)
    /// The core refused remote data (`Integrity { kind }`).
    case refused(kind: String)
    /// The iCloud account is not the one this store first synced with: sync stopped until
    /// `SyncCoordinator.acceptAccountChange()`.
    case accountChanged

    /// French text for the UI.
    public var label: String {
        switch self {
        case .disabled: "Synchronisation désactivée"
        case .idle: "À jour"
        case .syncing: "Synchronisation en cours"
        case .offline: "Hors ligne"
        case .error(let message): message
        case .refused(let kind): "Données refusées : \(VaultError.integrityLabel(kind))"
        case .accountChanged: "Le compte iCloud a changé"
        }
    }
}
