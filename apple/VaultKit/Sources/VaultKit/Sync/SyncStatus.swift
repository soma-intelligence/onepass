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
    /// The server serves an older or incomplete state (`ServerBehind`), or a safe exit waits for the
    /// server to serve this device's state back: a sync state, never an integrity refusal (spec 3.1).
    case waitingForServer
    /// The iCloud account is not the one this store first synced with: sync stopped until
    /// `SyncCoordinator.acceptAccountChange(expected:)`.
    case accountChanged
    /// A mailbox account: the server serves an older state, or a safe exit waits for it.
    case waitingForMailbox
    /// The account's signed home names another server (or iCloud): this device sends nothing more
    /// until it follows. `server`: the host, or "iCloud".
    case homeMoved(server: String)

    /// French text for the UI.
    public var label: String {
        switch self {
        case .disabled: String(localized: "sync.syncOff", bundle: VaultKitStrings.bundle)
        case .idle: String(localized: "sync.upToDate", bundle: VaultKitStrings.bundle)
        case .syncing: String(localized: "sync.syncing", bundle: VaultKitStrings.bundle)
        case .offline: String(localized: "sync.offline", bundle: VaultKitStrings.bundle)
        case .error(let message): message
        case .refused(let kind): String(localized: "vaultKit.dataRefused \(VaultError.integrityLabel(kind))", bundle: VaultKitStrings.bundle)
        case .accountChanged: String(localized: "sync.icloudAccountChanged", bundle: VaultKitStrings.bundle)
        case .waitingForServer: String(localized: "sync.syncWaitingForIcloud", bundle: VaultKitStrings.bundle)
        case .waitingForMailbox: String(localized: "sync.status.waitingForMailbox", bundle: VaultKitStrings.bundle)
        case .homeMoved: String(localized: "sync.status.homeMoved", bundle: VaultKitStrings.bundle)
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
        String(localized: "sync.icloudAccountAlreadyHolds", bundle: VaultKitStrings.bundle)
    }
}


/// Safe exits of "Données refusées" (spec 3.3): each issues a signed restore epoch.
public enum SafeExit: Equatable, Sendable {
    /// "Garder la version de cet appareil": this device's verified copies are sent over the server's.
    case keepThisDevice
    /// "Prendre la version d'iCloud": the server's state is taken, unsent local changes are dropped.
    case takeServer
}
