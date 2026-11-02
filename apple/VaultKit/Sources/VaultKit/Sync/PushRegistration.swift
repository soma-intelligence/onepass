import CryptoKit
import Foundation

/// Silent APNs wakes for an account on a mailbox (cross-platform spec 4.10). The app never asks for
/// the visible-notification permission: `registerForRemoteNotifications` only. A token goes to the
/// mailbox once, then again only when it changes (its SHA-256 in the store meta, never the token).
/// A refused registration changes nothing: the sync still runs at each opening and through the
/// Realtime wake in the foreground.
public actor PushRegistration {
    static let metaKey = "push.token.sha256"
    /// Time a silent push may take (the system gives about 30 s).
    public static let budget: Duration = .seconds(25)

    private let sync: any MailboxSyncing
    private let store: SyncStoreHandle
    private let budget: Duration

    public init(sync: any MailboxSyncing, store: SyncStoreHandle, budget: Duration = PushRegistration.budget) {
        self.sync = sync
        self.store = store
        self.budget = budget
    }

    /// The system gave a device token.
    public func didRegister(token: Data) async {
        let digest = Data(SHA256.hash(data: token))
        let store = store
        let known = try? await CoreThread.run { try store.meta(key: Self.metaKey) }
        if known == digest { return }
        do {
            try await sync.setPushToken(kind: .apns, token: token)
            try await CoreThread.run { try store.setMeta(key: Self.metaKey, value: digest) }
        } catch {
            // Sent again at the next registration (each launch).
        }
    }

    /// The system refused the registration: nothing is shown, nothing changes.
    public func didFail() async {}

    /// A silent push arrived: one round (`run`), cut at the budget. True when it finished in time.
    public func didReceiveSilent(run: @escaping @Sendable () async -> Void) async -> Bool {
        let budget = budget
        return await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await run()
                return true
            }
            group.addTask {
                try? await Task.sleep(for: budget)
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
    }
}
