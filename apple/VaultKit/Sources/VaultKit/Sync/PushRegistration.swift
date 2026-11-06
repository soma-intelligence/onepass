import CryptoKit
import Foundation
import Security

/// Silent APNs wakes for an account on a mailbox (cross-platform spec 4.10). The app never asks for
/// the visible-notification permission: `registerForRemoteNotifications` only. A token goes to the
/// mailbox once, then again only when it changes (its SHA-256 in the store meta, never the token).
/// A refused registration changes nothing: the sync still runs at each opening and through the
/// Realtime wake in the foreground.
public actor PushRegistration {
    static let metaKey = "push.token.sha256"
    /// Time a silent push may take (the system gives about 30 s).
    public static let budget: Duration = .seconds(25)

    /// Store meta keys of a zone mailbox's push target (sharing spec 13.7): the tag drawn once by
    /// this device for that mailbox, and the SHA-256 of the token last registered there.
    static func zoneTagKey(_ mailboxID: String) -> String { "push.zone.tag.\(mailboxID)" }
    static func zoneTokenKey(_ mailboxID: String) -> String { "push.zone.sha256.\(mailboxID)" }

    private let sync: (any MailboxSyncing)?
    private let zones: (any ZoneSyncing)?
    private let store: SyncStoreHandle
    private let budget: Duration

    /// `sync`: the account's mailbox (nil for an iCloud account); `zones`: its zone mailboxes.
    public init(
        sync: (any MailboxSyncing)?, store: SyncStoreHandle, zones: (any ZoneSyncing)? = nil,
        budget: Duration = PushRegistration.budget
    ) {
        self.sync = sync
        self.zones = zones
        self.store = store
        self.budget = budget
    }

    /// The system gave a device token: the account mailbox, then one target per zone mailbox.
    public func didRegister(token: Data) async {
        let digest = Data(SHA256.hash(data: token))
        let store = store
        if let sync {
            let known = try? await CoreThread.run { try store.meta(key: Self.metaKey) }
            if known != digest {
                do {
                    try await sync.setPushToken(kind: .apns, token: token)
                    try await CoreThread.run { try store.setMeta(key: Self.metaKey, value: digest) }
                } catch {
                    // Sent again at the next registration (each launch).
                }
            }
        }
        await registerZones(token: token, digest: digest)
    }

    /// One push target per zone mailbox under a tag drawn at random by this device for that mailbox
    /// (the server never links two mailboxes of one device). A zone already registered with this
    /// token is skipped; a failure is retried at the next registration.
    private func registerZones(token: Data, digest: Data) async {
        guard let zones else { return }
        let store = store
        for wake in await zones.wakeTopics() {
            let mailbox = wake.mailboxId
            let known = try? await CoreThread.run { try store.meta(key: Self.zoneTokenKey(mailbox)) }
            if known == digest { continue }
            do {
                let tag = try await CoreThread.run { () throws -> Data in
                    if let tag = try store.meta(key: Self.zoneTagKey(mailbox)), tag.count == 16 { return tag }
                    var bytes = Data(count: 16)
                    let status = bytes.withUnsafeMutableBytes {
                        SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
                    }
                    guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
                    try store.setMeta(key: Self.zoneTagKey(mailbox), value: bytes)
                    return bytes
                }
                try await zones.setPushTarget(mailboxID: mailbox, tag: tag, kind: .apns, token: token)
                try await CoreThread.run { try store.setMeta(key: Self.zoneTokenKey(mailbox), value: digest) }
            } catch {
                // Registered again at the next launch.
            }
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
