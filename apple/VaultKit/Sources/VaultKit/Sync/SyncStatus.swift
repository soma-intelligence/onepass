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
    /// `SyncCoordinator.acceptAccountChange(expected:)`.
    case accountChanged

    /// French text for the UI.
    public var label: String {
        switch self {
        case .disabled: String(localized: "Synchronisation désactivée", bundle: VaultKitStrings.bundle)
        case .idle: String(localized: "À jour", bundle: VaultKitStrings.bundle)
        case .syncing: String(localized: "Synchronisation en cours", bundle: VaultKitStrings.bundle)
        case .offline: String(localized: "Hors ligne", bundle: VaultKitStrings.bundle)
        case .error(let message): message
        case .refused(let kind): String(localized: "Données refusées : \(VaultError.integrityLabel(kind))", bundle: VaultKitStrings.bundle)
        case .accountChanged: String(localized: "Le compte iCloud a changé", bundle: VaultKitStrings.bundle)
        }
    }
}

/// What the zone of a newly signed-in iCloud account holds (`SyncCoordinator.checkAccountChange`).
public enum AccountChangeCheck: Equatable, Sendable {
    /// The same OnePass account as this store (same account id).
    case sameVault
    /// No OnePass account: accepting uploads the encrypted vault there.
    case emptyZone
    /// Another OnePass account: refused.
    case otherVault
}

/// Result of `SyncCoordinator.acceptAccountChange(expected:)`.
public enum AccountChangeOutcome: Equatable, Sendable {
    case accepted
    /// The zone holds another OnePass account: nothing changed, sync stays stopped.
    case refusedOtherVault
    /// The zone no longer holds what the user confirmed, or the signed-in account changed during the
    /// check: nothing changed, the user checks again.
    case changedDuringCheck
    /// French message for the UI.
    case failed(String)

    /// The refusal shown to the user.
    public static var otherVaultMessage: String {
        String(localized: "Ce compte iCloud contient déjà un autre coffre OnePass. Reviens au compte iCloud d'origine pour synchroniser.", bundle: VaultKitStrings.bundle)
    }
}

