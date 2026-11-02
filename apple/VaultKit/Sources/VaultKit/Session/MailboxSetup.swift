import Foundation
import os

/// The mailbox calls that make or open a mailbox, as the setup, the restore and the migration use
/// them. The app uses `FfiMailboxProvisioning`; tests script a fake.
public protocol MailboxProvisioning: Sendable {
    /// `GET /v1/config` of a server: reachable, speaks the protocol, open signup or not.
    func check(_ endpoint: FfiMailboxEndpoint) async throws -> FfiMailboxServerInfo
    func generateCredential() async throws -> FfiMailboxCredential
    /// A new mailbox on `endpoint`, managed by the credential of `seed`.
    func create(_ endpoint: FfiMailboxEndpoint, seed: Data, invite: String?) async throws -> FfiMailboxHome
    /// The sync client of `home`, signed by the credential of `seed`.
    func open(_ home: MailboxHome, seed: Data) async throws -> any MailboxSyncing
    /// The mailboxes registered under `locator` on `endpoint` (hex ids, oldest first).
    func locate(_ endpoint: FfiMailboxEndpoint, locator: Data) async throws -> [String]
}

/// The core's mailbox functions, each on the core thread (they block on the network).
public struct FfiMailboxProvisioning: MailboxProvisioning {
    /// The store the sync clients rebase into.
    public let databasePath: String

    public init(databasePath: String) {
        self.databasePath = databasePath
    }

    public func check(_ endpoint: FfiMailboxEndpoint) async throws -> FfiMailboxServerInfo {
        try await CoreThread.run { try mailboxServerCheck(endpoint: endpoint) }
    }

    public func generateCredential() async throws -> FfiMailboxCredential {
        try await CoreThread.run { try mailboxGenerateCredential() }
    }

    public func create(_ endpoint: FfiMailboxEndpoint, seed: Data, invite: String?) async throws -> FfiMailboxHome {
        try await CoreThread.run { try mailboxCreate(endpoint: endpoint, credentialSeed: seed, invite: invite) }
    }

    public func open(_ home: MailboxHome, seed: Data) async throws -> any MailboxSyncing {
        let path = databasePath
        let sync = try await CoreThread.run {
            try MailboxSync.open(dbPath: path, endpoint: home.endpoint, mailboxId: home.mailboxID, credentialSeed: seed)
        }
        return FfiMailboxSyncAdapter(sync: sync)
    }

    public func locate(_ endpoint: FfiMailboxEndpoint, locator: Data) async throws -> [String] {
        try await CoreThread.run { try mailboxLocate(endpoint: endpoint, locator: locator) }
    }
}

/// How a mailbox setup ended.
public enum MailboxSetupOutcome: Equatable, Sendable {
    /// The account syncs with this mailbox.
    case ready(MailboxHome)
    /// The account syncs with iCloud (its choice).
    case iCloud
    /// The server could not be reached: the account stays on this device, the setup resumes later.
    case offline
    case failed(String)
}

/// Puts a new account on a mailbox (cross-platform spec D.2, D.4): device credential, mailbox,
/// recovery credential granted, locator registered, signed home adopted, backend state written.
/// Each step is recorded in the store meta (`mailbox.setup`) before the next one starts, so a cut
/// at any point resumes where it stopped and never creates a second mailbox. The recovery
/// credential's seed is derived from the Secret Key and never stored.
public actor MailboxSetup {
    /// The steps done, in order.
    enum Step: Int, Codable, Comparable, Sendable {
        case started = 0, credential, created, recoveryGranted, locatorSet, homeAdopted, done

        static func < (a: Step, b: Step) -> Bool { a.rawValue < b.rawValue }
    }

    /// What the store remembers of a setup in progress.
    struct Progress: Codable, Equatable, Sendable {
        var step: Step
        var baseURL: URL
        var extraCAPEM: String?
        var mailboxID: String?
    }

    static let metaKey = "mailbox.setup"
    /// The keychain slot of the device seed before the mailbox id is known.
    static let pendingID = "pending"
    /// The grant label of the recovery credential: the server sees it, it names a role only.
    static let recoveryLabel = Data("recovery".utf8)

    private let provisioning: any MailboxProvisioning
    private let credentials: MailboxCredentialStore
    private let store: SyncStoreHandle
    private let hosted: URL?
    /// Tests: stop (as a crash would) right after this step is recorded.
    var interruptAfter: Step?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "mailbox-setup")

    /// `hosted`: the OnePass server of this build (`MailboxEndpoints.hosted()`).
    public init(
        provisioning: any MailboxProvisioning, credentials: MailboxCredentialStore, store: SyncStoreHandle,
        hosted: URL? = MailboxEndpoints.hosted()
    ) {
        self.provisioning = provisioning
        self.credentials = credentials
        self.store = store
        self.hosted = hosted
    }

    func setInterruptAfter(_ step: Step?) { interruptAfter = step }

    /// Run (or resume) the setup for `choice` on the unlocked `session`.
    public func run(session: Session, choice: SyncChoice, secretKey: SecretBytes) async -> MailboxSetupOutcome {
        await guarded { try await self.steps(session: session, choice: choice, secretKey: secretKey, migrating: false) }
    }

    /// Steps 1 to 4 only, for a migration (spec D.5): the mailbox is made and reachable by the
    /// recovery credential and the locator, but the account's home is untouched (the migration
    /// claims it in iCloud first) and the backend state stays what it is.
    public func prepareForMigration(session: Session, choice: SyncChoice, secretKey: SecretBytes) async -> MailboxSetupOutcome {
        guard choice != .iCloud else { return .iCloud }
        return await guarded { try await self.steps(session: session, choice: choice, secretKey: secretKey, migrating: true) }
    }

    private func guarded(_ body: () async throws -> MailboxSetupOutcome) async -> MailboxSetupOutcome {
        do {
            return try await body()
        } catch Interrupted.now {
            return .failed("interrupted")
        } catch let error as OnePassError {
            if case .MailboxUnavailable = error { return .offline }
            Self.log.error("mailbox setup failed")
            return .failed(VaultError(error).localizedMessage)
        } catch {
            Self.log.error("mailbox setup failed")
            return .failed(VaultError(error).localizedMessage)
        }
    }

    private enum Interrupted: Error { case now }

    private func steps(
        session: Session, choice: SyncChoice, secretKey: SecretBytes, migrating: Bool
    ) async throws -> MailboxSetupOutcome {
        var progress = try await readProgress()
        if progress == nil {
            let base: URL
            let ca: String?
            switch choice {
            case .iCloud:
                // The CloudKit coordinator writes the CloudKit home on its first round.
                try await SyncBackendState.write(.iCloud, store: store)
                return .iCloud
            case .hosted:
                guard let hosted else { return .failed(Self.noHostedMessage) }
                (base, ca) = (hosted, nil)
            case .selfHost(let url, let pem):
                guard MailboxEndpoints.validate(url, allowHTTP: MailboxEndpoints.allowsLocalHTTP) else {
                    return .failed(Self.badURLMessage)
                }
                (base, ca) = (url, pem)
            }
            if !migrating { try await SyncBackendState.write(.pendingSetup(choice), store: store) }
            progress = Progress(step: .started, baseURL: base, extraCAPEM: ca, mailboxID: nil)
            try await save(progress!)
        }
        var p = progress!
        let endpoint = FfiMailboxEndpoint(baseUrl: p.baseURL.absoluteString, extraCaPem: p.extraCAPEM)

        // 1. This device's credential, kept before the server knows it.
        if p.step < .credential {
            let credential = try await provisioning.generateCredential()
            try credentials.store(seed: SecretBytes(copying: credential.seed), mailboxID: Self.pendingID)
            try await advance(&p, to: .credential)
        }
        // 2. The mailbox, managed by that credential.
        if p.step < .created {
            guard let seed = try credentials.seed(mailboxID: Self.pendingID) else {
                throw OnePassError.InvalidInput(what: "mailbox credential")
            }
            let created = try await provisioning.create(endpoint, seed: seed.withData { Data($0) }, invite: nil)
            try credentials.store(seed: seed, mailboxID: created.mailboxId)
            try credentials.delete(mailboxID: Self.pendingID)
            p.mailboxID = created.mailboxId
            try await advance(&p, to: .created)
        }
        guard let mailboxID = p.mailboxID, let seed = try credentials.seed(mailboxID: mailboxID) else {
            throw OnePassError.InvalidInput(what: "mailbox credential")
        }
        let home = MailboxHome(baseURL: p.baseURL, mailboxID: mailboxID, extraCAPEM: p.extraCAPEM)
        let sync = try await provisioning.open(home, seed: seed.withData { Data($0) })
        let key = secretKey.withData { String(decoding: $0, as: UTF8.self) }

        // 3. The recovery credential, derived from the Secret Key, granted, then forgotten.
        if p.step < .recoveryGranted {
            let recovery = try await CoreThread.run {
                try mailboxRecoveryCredential(secretKey: key, mailboxId: mailboxID)
            }
            do {
                _ = try await sync.grant(publicKey: recovery.publicKey, role: .manage, label: Self.recoveryLabel)
            } catch OnePassError.Conflict {
                // Granted before a cut: the server already holds it.
            }
            try await advance(&p, to: .recoveryGranted)
        }
        // 4. The locator a restore looks the mailbox up by.
        if p.step < .locatorSet {
            let locator = try await CoreThread.run { try mailboxLocator(secretKey: key) }
            try await sync.setLocator(locator)
            try await advance(&p, to: .locatorSet)
        }
        if migrating { return .ready(home) }
        // 5. The account's signed home names the mailbox.
        if p.step < .homeAdopted {
            let backend = home.backend
            try await CoreThread.run {
                if let current = try session.syncHome(), current.backend == backend { return }
                _ = try session.adoptSyncHome(home: try session.signSyncHome(backend: backend))
            }
            try await advance(&p, to: .homeAdopted)
        }
        // 6. The app syncs with it from now on.
        try await SyncBackendState.write(.mailbox(home), store: store)
        try await advance(&p, to: .done)
        return .ready(home)
    }

    /// Drop the progress of an abandoned setup (a migration that lost its claim): the next setup
    /// starts from a new credential and a new mailbox.
    public func forget() async {
        let store = store
        try? await CoreThread.run { try store.setMeta(key: Self.metaKey, value: Data()) }
    }

    private func advance(_ p: inout Progress, to step: Step) async throws {
        p.step = step
        try await save(p)
        if let interruptAfter, step == interruptAfter { throw Interrupted.now }
    }

    private func readProgress() async throws -> Progress? {
        let store = store
        let data = try await CoreThread.run { try store.meta(key: Self.metaKey) }
        guard let data, !data.isEmpty else { return nil }
        return try JSONDecoder().decode(Progress.self, from: data)
    }

    private func save(_ p: Progress) async throws {
        let store = store
        let data = try JSONEncoder().encode(p)
        try await CoreThread.run { try store.setMeta(key: Self.metaKey, value: data) }
    }

    static var noHostedMessage: String {
        String(localized: "sync.setup.noHostedServer", bundle: VaultKitStrings.bundle)
    }

    static var badURLMessage: String {
        String(localized: "sync.setup.badURL", bundle: VaultKitStrings.bundle)
    }
}

extension VaultSession {
    /// Run `setup` on this unlocked session; nil while locked.
    public func runMailboxSetup(
        _ setup: MailboxSetup, choice: SyncChoice, secretKey: SecretBytes
    ) async -> MailboxSetupOutcome? {
        guard let core = coreSession else { return nil }
        return await setup.run(session: core, choice: choice, secretKey: secretKey)
    }
}
