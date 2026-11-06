import Foundation
import os

/// Where a restore from the Emergency Kit finds the account (cross-platform spec D.4).
public enum RestoreSource: Equatable, Sendable {
    case mailbox(MailboxHome)
    case iCloud
    case notFound
    /// No server answered: nothing can be said yet.
    case offline
}

/// Restores an account kept on a mailbox, from the Secret Key alone (spec D.4). The kit's server
/// (self-host) is asked first, then the OnePass server by the account's locator, then iCloud. The
/// recovery credential, derived from the Secret Key and never stored, fetches the whole mailbox
/// into the store; this device gets its own credential only after the master password unlocked the
/// account, so a wrong password leaves nothing granted and nothing in the keychain.
public actor MailboxRestore {
    private let provisioning: any MailboxProvisioning
    private let credentials: MailboxCredentialStore
    private let hosted: URL?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "mailbox-restore")

    public init(
        provisioning: any MailboxProvisioning, credentials: MailboxCredentialStore,
        hosted: URL? = MailboxEndpoints.hosted()
    ) {
        self.provisioning = provisioning
        self.credentials = credentials
        self.hosted = hosted
    }

    /// Find the account of `secretKey`. `kitServer`: the server line of a self-host kit.
    public func locate(
        secretKey: SecretBytes, kitServer: URL?, iCloudHasAccount: @Sendable () async -> Bool
    ) async -> RestoreSource {
        let key = secretKey.withData { String(decoding: $0, as: UTF8.self) }
        guard let locator = try? await CoreThread.run({ try mailboxLocator(secretKey: key) }) else {
            return .notFound
        }
        var unreachable = false
        for base in [kitServer, hosted].compactMap({ $0 }) {
            let endpoint = FfiMailboxEndpoint(baseUrl: base.absoluteString, extraCaPem: nil)
            do {
                // Oldest first: the account's first mailbox is the one its home names.
                if let id = try await provisioning.locate(endpoint, locator: locator).first {
                    return .mailbox(MailboxHome(baseURL: base, mailboxID: id))
                }
            } catch {
                unreachable = true
            }
        }
        if await iCloudHasAccount() { return .iCloud }
        return unreachable ? .offline : .notFound
    }

    /// Fetch the mailbox of `home` into the store with the recovery credential, then `unlock`
    /// (the master password). Once unlocked: this device's credential is generated, granted by the
    /// recovery credential and kept; the backend state names the mailbox. Returns the device's
    /// client. `unlock` throwing ends the restore with nothing granted or stored.
    public func restore(
        home: MailboxHome, secretKey: SecretBytes, store: SyncStoreHandle,
        unlock: @Sendable () async throws -> Session
    ) async throws -> any MailboxSyncing {
        let key = secretKey.withData { String(decoding: $0, as: UTF8.self) }
        let recovery = try await CoreThread.run {
            try mailboxRecoveryCredential(secretKey: key, mailboxId: home.mailboxID)
        }
        let recoveryClient = try await provisioning.open(home, seed: recovery.seed)
        let fetched = await recoveryClient.runRound(session: nil, now: Int64(Date().timeIntervalSince1970))
        switch fetched.status {
        case .idle, .waitingForServer, .unsettled: break
        default:
            Self.log.error("mailbox restore fetch failed")
            throw OnePassError.MailboxUnavailable(reason: "restore fetch")
        }
        let session = try await unlock()
        let device = try await provisioning.generateCredential()
        _ = try await recoveryClient.grant(publicKey: device.publicKey, role: .manage, label: Data())
        try credentials.store(seed: SecretBytes(copying: device.seed), mailboxID: home.mailboxID)
        try await SyncBackendState.write(.mailbox(home), store: store)
        let client = try await provisioning.open(home, seed: device.seed)
        // The rebase of what the recovery fetch staged, signed by this device from now on.
        _ = await client.runRound(session: session, now: Int64(Date().timeIntervalSince1970))
        return client
    }
}

extension VaultSession {
    /// Restore through `restore`: the mailbox is fetched, then `unlock` (the master password on
    /// this session) runs, then this device gets its credential. Returns the device's client.
    public func restoreMailbox(
        _ restore: MailboxRestore, home: MailboxHome, secretKey: SecretBytes, store: SyncStoreHandle,
        unlock: @escaping @MainActor () async throws -> Void
    ) async throws -> any MailboxSyncing {
        try await restore.restore(home: home, secretKey: secretKey, store: store) { @MainActor [weak self] in
            try await unlock()
            guard let core = self?.coreSession else { throw OnePassError.Locked }
            return core
        }
    }
}
