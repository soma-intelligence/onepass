import Foundation
import os

/// Moves an iCloud account to a mailbox, on the device that starts it (cross-platform spec D.5,
/// steps 1 to 3). Order, each step recorded in the store meta (`migration.state`) so a cut resumes:
///
/// 1. The mailbox is made (`MailboxSetup.prepareForMigration`: credential, mailbox, recovery
///    credential, locator). The account's home is untouched.
/// 2. The new signed home is claimed in iCloud by a conditional write on the `SyncHome` record.
///    Only the winner of that write goes on: a device that loses adopts the winner's home,
///    abandons its fresh mailbox and follows. Nothing is adopted before the claim is won.
/// 3. The home is adopted, the CloudKit coordinator stops (no more iCloud sends), the store
///    queues every record again for the mailbox and the router switches to the mailbox
///    coordinator, whose rounds upload the vault.
public actor MailboxMigration {
    public enum State: Codable, Equatable, Sendable {
        case idle
        case mailboxReady(MailboxHome)
        case claimed(MailboxHome, signed: Data)
        case uploading(MailboxHome)
        case done(MailboxHome, migratedAt: Date)
    }

    public enum Outcome: Equatable, Sendable {
        case done(MailboxHome)
        /// Another device claimed first; `winner` is its home when it names a mailbox.
        case lostRace(winner: MailboxHome?)
        case blocked(Blocker)
        case failed(String)
    }

    /// Why a migration cannot start now.
    public enum Blocker: Equatable, Sendable {
        case locked, notSynced, refused, rotating, offline
    }

    /// What the migration acts on, besides the store.
    public struct Parts: Sendable {
        public var setup: MailboxSetup
        public var provisioning: any MailboxProvisioning
        public var credentials: MailboxCredentialStore
        /// The account's iCloud zone.
        public var remote: any RemoteRecordStore
        public var cloudKit: SyncCoordinator
        public var router: SyncRouter
        /// The mailbox coordinator of the home, around its client.
        public var makeCoordinator: @Sendable (any MailboxSyncing, MailboxHome) async -> MailboxSyncCoordinator

        public init(
            setup: MailboxSetup, provisioning: any MailboxProvisioning, credentials: MailboxCredentialStore,
            remote: any RemoteRecordStore, cloudKit: SyncCoordinator, router: SyncRouter,
            makeCoordinator: @escaping @Sendable (any MailboxSyncing, MailboxHome) async -> MailboxSyncCoordinator
        ) {
            self.setup = setup
            self.provisioning = provisioning
            self.credentials = credentials
            self.remote = remote
            self.cloudKit = cloudKit
            self.router = router
            self.makeCoordinator = makeCoordinator
        }
    }

    static let metaKey = "migration.state"
    /// The mailbox change cursor the core's sync keeps (`onepass_sync::policy::CURSOR_KEY`).
    static let mailboxCursorKey = "mailbox.cursor"

    private let store: SyncStoreHandle
    private let parts: Parts
    private let now: @Sendable () -> Date
    /// Tests: stop (as a crash would) right after a state this returns true for is recorded.
    private var interruptAfter: (@Sendable (State) -> Bool)?
    /// Tests: runs just before the claim is sent.
    private var beforeClaim: (@Sendable () async -> Void)?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "mailbox-migration")

    public init(store: SyncStoreHandle, parts: Parts, now: @escaping @Sendable () -> Date = { Date() }) {
        self.store = store
        self.parts = parts
        self.now = now
    }

    func setInterruptAfter(_ match: (@Sendable (State) -> Bool)?) { interruptAfter = match }
    func setBeforeClaim(_ hook: (@Sendable () async -> Void)?) { beforeClaim = hook }

    /// Why the migration cannot start, nil when it can: an unlocked session, an iCloud sync that
    /// last ended idle, no refusal, no key rotation in progress.
    public func preflight(session: Session?, status: SyncStatus) async -> Blocker? {
        guard let session else { return .locked }
        switch status {
        case .idle(let last) where last != nil: break
        case .offline: return .offline
        case .refused: return .refused
        default: return .notSynced
        }
        // A rotation waiting for this device's answer: the new home would be signed by keys about
        // to change.
        let pending = try? await CoreThread.run { try session.pendingRotation() }
        return (pending ?? nil) != nil ? .rotating : nil
    }

    /// The state recorded in the store.
    public func state() async -> State {
        let store = store
        let read = try? await CoreThread.run { try store.meta(key: Self.metaKey) }
        guard let data = read ?? nil, !data.isEmpty,
              let state = try? JSONDecoder().decode(State.self, from: data)
        else { return .idle }
        return state
    }

    /// Start (or resume) the migration to `choice`.
    public func start(choice: SyncChoice, session: Session, secretKey: SecretBytes) async -> Outcome {
        do {
            return try await steps(choice: choice, session: session, secretKey: secretKey)
        } catch Interrupted.now {
            return .failed("interrupted")
        } catch let error as OnePassError {
            if case .MailboxUnavailable = error { return .blocked(.offline) }
            return .failed(VaultError(error).localizedMessage)
        } catch RemoteStoreError.offline {
            return .blocked(.offline)
        } catch {
            return .failed(VaultError(error).localizedMessage)
        }
    }

    /// At launch: a migration cut after its claim resumes its upload (no new mailbox).
    public func resume(session: Session?) async -> Outcome? {
        switch await state() {
        case .idle, .mailboxReady, .done: return nil
        case .claimed, .uploading:
            guard let session else { return nil }
            do {
                return try await steps(choice: .hosted, session: session, secretKey: nil)
            } catch {
                return .failed(VaultError(error).localizedMessage)
            }
        }
    }

    private enum Interrupted: Error { case now }

    private func steps(choice: SyncChoice, session: Session, secretKey: SecretBytes?) async throws -> Outcome {
        var state = await state()
        // 1. The mailbox.
        if case .idle = state {
            guard let secretKey else { return .failed("secret key") }
            switch await parts.setup.prepareForMigration(session: session, choice: choice, secretKey: secretKey) {
            case .ready(let home): state = .mailboxReady(home)
            case .offline: return .blocked(.offline)
            case .failed(let message): return .failed(message)
            case .iCloud: return .failed("iCloud")
            }
            try await record(state)
        }
        // 2. The claim in iCloud.
        if case .mailboxReady(let home) = state {
            let signed = try await CoreThread.run { try session.signSyncHome(backend: home.backend) }
            let claim = try await claimRecord(session: session, signed: signed)
            await beforeClaim?()
            let result = try await parts.remote.send([claim]).first
            switch result {
            case .saved:
                state = .claimed(home, signed: signed)
                try await record(state)
            case .conflict(let server):
                return try await lost(to: server, home: home, session: session)
            case .failed, .none:
                return .failed("claim")
            }
        }
        // 3. Adopt, stop iCloud, queue everything for the mailbox, switch.
        if case .claimed(let home, let signed) = state {
            _ = try await CoreThread.run { try session.adoptSyncHome(home: signed) }
            await parts.cloudKit.stopForMigration()
            let store = store
            try await CoreThread.run { try store.beginZoneReset(tokenKey: Self.mailboxCursorKey) }
            state = .uploading(home)
            try await record(state)
        }
        if case .uploading(let home) = state {
            await parts.cloudKit.stopForMigration()
            guard let seed = try parts.credentials.seed(mailboxID: home.mailboxID) else {
                return .failed("mailbox credential")
            }
            let client = try await parts.provisioning.open(home, seed: seed.withData { Data($0) })
            try await SyncBackendState.write(.mailbox(home), store: store)
            let coordinator = await parts.makeCoordinator(client, home)
            await parts.router.switchTo(coordinator)
            state = .done(home, migratedAt: now())
            try await record(state)
            return .done(home)
        }
        if case .done(let home, _) = state { return .done(home) }
        return .failed("state")
    }

    /// The `SyncHome` record of the account as the claim writes it: conditional on the version
    /// this device last saw in iCloud (none: the record must not exist).
    private func claimRecord(session: Session, signed: Data) async throws -> RemoteRecord {
        let store = store
        let (id, seq) = try await CoreThread.run { () -> (String, UInt64) in
            let id = try session.syncHomeRecordId()
            let seq = try session.syncHome()?.seq ?? 0
            return (id, seq + 1)
        }
        let kind = CloudKitMapping.syncHomeKind
        let meta = try await CoreThread.run { try store.serverMeta(kind: kind, id: id) }
        return RemoteRecord(name: RecordName(kind: kind, id: id), version: seq, data: signed, serverMeta: meta)
    }

    /// Another device's home won: adopt it (verified by the core against the account key),
    /// abandon the fresh mailbox and forget its credential.
    private func lost(to server: RemoteRecord, home: MailboxHome, session: Session) async throws -> Outcome {
        var winner: MailboxHome?
        if let data = server.data {
            let adopted = try await CoreThread.run { try session.adoptSyncHome(home: data) }
            if case .mailbox(let url, let id) = adopted.backend, let base = URL(string: url) {
                winner = MailboxHome(baseURL: base, mailboxID: id)
            }
        }
        if let seed = try parts.credentials.seed(mailboxID: home.mailboxID) {
            let client = try await parts.provisioning.open(home, seed: seed.withData { Data($0) })
            try? await client.abandon()
        }
        try parts.credentials.delete(mailboxID: home.mailboxID)
        await parts.setup.forget()
        try await record(.idle)
        Self.log.notice("migration lost the claim")
        return .lostRace(winner: winner)
    }

    private func record(_ state: State) async throws {
        let store = store
        let data = try JSONEncoder().encode(state)
        try await CoreThread.run { try store.setMeta(key: Self.metaKey, value: data) }
        if let interruptAfter, interruptAfter(state) { throw Interrupted.now }
    }
}

extension VaultSession {
    /// `migration.preflight` on this session (nil while locked: `.locked`).
    public func migrationBlocker(_ migration: MailboxMigration, status: SyncStatus) async -> MailboxMigration.Blocker? {
        await migration.preflight(session: coreSession, status: status)
    }

    /// Start the migration on this unlocked session.
    public func migrate(
        _ migration: MailboxMigration, choice: SyncChoice, secretKey: SecretBytes
    ) async -> MailboxMigration.Outcome {
        guard let core = coreSession else { return .blocked(.locked) }
        return await migration.start(choice: choice, session: core, secretKey: secretKey)
    }

    /// Resume a migration cut after its claim.
    public func resumeMigration(_ migration: MailboxMigration) async -> MailboxMigration.Outcome? {
        await migration.resume(session: coreSession)
    }
}
