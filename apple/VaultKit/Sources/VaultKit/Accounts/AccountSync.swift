import Foundation

/// The sync of an added account (multi-account spec 6, ruling P8). Its CloudKit zone is named after
/// the account id, unknown before the account is created or found: the coordinator is made at the
/// first unlock (or by `attach` for a sign in on a new device), then every call is forwarded to it.
/// Before that, writes and locks have nothing to sync.
public actor AccountSync: SyncTrigger {
    public typealias Factory = @Sendable (_ accountID: String) -> SyncCoordinator?

    private let make: Factory
    private var coordinator: SyncCoordinator?
    /// Told once, with the coordinator, when it is made (the app listens to its changes).
    private let made: @Sendable (SyncCoordinator) -> Void
    public nonisolated let syncsWithServer: Bool

    public init(
        syncsWithServer: Bool, make: @escaping Factory,
        made: @escaping @Sendable (SyncCoordinator) -> Void = { _ in }
    ) {
        self.syncsWithServer = syncsWithServer
        self.make = make
        self.made = made
    }

    /// The coordinator, once made.
    public var current: SyncCoordinator? { coordinator }
    /// The account whose zone the coordinator syncs, once made.
    public private(set) var accountID: String?

    /// Makes the coordinator of `accountID` now (sign in on a new device: the zone is fetched before any
    /// unlock). A coordinator already made for the account is kept.
    @discardableResult
    public func attach(accountID: String) -> SyncCoordinator? {
        if let coordinator { return coordinator }
        guard let made = make(accountID) else { return nil }
        coordinator = made
        self.accountID = accountID
        self.made(made)
        return made
    }

    public func localChangesWritten() async {
        await coordinator?.localChangesWritten()
    }

    public func sessionUnlocked(_ session: Session) async {
        let target = coordinator ?? attach(accountID: session.accountId())
        await target?.sessionUnlocked(session)
    }

    public func sessionLocked() async {
        await coordinator?.sessionLocked()
    }

    public func resetStore(with reset: @escaping @Sendable () throws -> Void) async throws {
        if let coordinator {
            try await coordinator.resetStore(with: reset)
        } else {
            try await CoreThread.run(reset)
        }
    }

    public func safeExitIssued(_ exit: SafeExit) async {
        await coordinator?.safeExitIssued(exit)
    }

    public func syncNow() async {
        await coordinator?.syncNow()
    }
}
