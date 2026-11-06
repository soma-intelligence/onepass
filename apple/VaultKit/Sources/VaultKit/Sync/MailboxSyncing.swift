import Foundation

/// A running wake listener (`start_wake_listener`): `stop` ends it.
public protocol WakeStopping: Sendable {
    func stop()
}

/// The sync of one account through one mailbox, as the coordinator and the setup flows use it. The
/// app talks to the Rust `MailboxSync` through `FfiMailboxSyncAdapter`; tests script a fake.
public protocol MailboxSyncing: Sendable {
    /// One round: fetch, rebase with an unlocked `session`, send. `now`: Unix seconds.
    func runRound(session: Session?, now: Int64) async -> FfiRoundReport
    func wakeInfo() async throws -> FfiWakeInfo
    /// Listen to the mailbox's wake channel; `onWake` runs on the listener's thread.
    func startWake(_ onWake: @escaping @Sendable () -> Void) async throws -> any WakeStopping
    func setPushToken(kind: FfiPushKind, token: Data) async throws
    /// Let `publicKey` in with `role` (manager only). Returns the credential's hex id.
    func grant(publicKey: Data, role: FfiCredentialRole, label: Data) async throws -> String
    func setLocator(_ locator: Data) async throws
    func abandon() async throws
}

/// `MailboxSync` of the core, each call on the core thread (every call blocks on the network).
public struct FfiMailboxSyncAdapter: MailboxSyncing {
    public let sync: MailboxSync

    public init(sync: MailboxSync) {
        self.sync = sync
    }

    public func runRound(session: Session?, now: Int64) async -> FfiRoundReport {
        let sync = sync
        let report = try? await CoreThread.run { sync.runRound(session: session, now: now) }
        return report ?? FfiRoundReport(status: .retrying, changed: false, rebased: [], retryAfterSeconds: nil, rerun: false)
    }

    public func wakeInfo() async throws -> FfiWakeInfo {
        let sync = sync
        return try await CoreThread.run { try sync.wakeInfo() }
    }

    public func startWake(_ onWake: @escaping @Sendable () -> Void) async throws -> any WakeStopping {
        let info = try await wakeInfo()
        let handle = try await CoreThread.run {
            try startWakeListener(info: info, observer: WakeObserver(onWake))
        }
        return WakeHandle(handle: handle)
    }

    public func setPushToken(kind: FfiPushKind, token: Data) async throws {
        let sync = sync
        try await CoreThread.run { try sync.setPushToken(kind: kind, token: token) }
    }

    public func grant(publicKey: Data, role: FfiCredentialRole, label: Data) async throws -> String {
        let sync = sync
        return try await CoreThread.run { try sync.grant(publicKey: publicKey, role: role, label: label) }
    }

    public func setLocator(_ locator: Data) async throws {
        let sync = sync
        try await CoreThread.run { try sync.setLocator(locator: locator) }
    }

    public func abandon() async throws {
        let sync = sync
        try await CoreThread.run { try sync.abandon() }
    }
}

private final class WakeObserver: FfiWakeObserver, @unchecked Sendable {
    private let onWake: @Sendable () -> Void

    init(_ onWake: @escaping @Sendable () -> Void) {
        self.onWake = onWake
    }

    func wake() { onWake() }
}

private struct WakeHandle: WakeStopping {
    let handle: WakeListenerHandle

    func stop() { handle.stop() }
}
