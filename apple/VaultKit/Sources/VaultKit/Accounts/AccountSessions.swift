import Foundation
import Observation
import os

/// Why an account operation was refused.
public enum AccountsError: Error, Equatable, Sendable {
    /// A managed account needs its organisation's server, which this version cannot reach yet
    /// (multi-account spec 3.1, ruling P11).
    case serverUnavailable
    /// The directory could not be written or holds no such account.
    case directory(VaultError)
    /// The account is already on this device in another slot (M5).
    case alreadyOnDevice
    /// The primary account is reset, never removed (M8).
    case primaryAccount

    public var message: String {
        switch self {
        case .serverUnavailable:
            String(localized: "accounts.error.serverUnavailable", bundle: VaultKitStrings.bundle)
        case .directory(let error): error.localizedMessage
        case .alreadyOnDevice:
            String(localized: "accounts.error.alreadyOnDevice", bundle: VaultKitStrings.bundle)
        case .primaryAccount:
            String(localized: "accounts.error.primaryAccount", bundle: VaultKitStrings.bundle)
        }
    }
}

/// A search result of the "All accounts" view: the summary and the account it belongs to.
public struct UnifiedResult: Identifiable, Equatable, Sendable {
    public let account: AccountProfile
    public let summary: FfiItemSummary
    public var id: String { "\(account.slot):\(summary.vaultId):\(summary.id)" }
}

/// Every account of the device and their sessions (multi-account spec 6): one `VaultSession` per
/// account, each with its own store, settings scope, lock and Secret Key; the same keychain, whose
/// entries are already named by account id. Nothing here derives or moves a key between accounts.
@MainActor
@Observable
public final class AccountSessions {
    /// Builds the environment of an added account: its store file and settings scope, the app's
    /// keychain, biometrics and clock.
    public typealias EnvironmentFactory = @MainActor (_ slot: String, _ databaseURL: URL, _ settings: VaultSettings)
        -> VaultEnvironment

    /// The accounts in display order, primary first.
    public private(set) var profiles: [AccountProfile] = []
    /// The account shown.
    public private(set) var activeSlot: String = AccountDirectoryStore.primarySlot
    /// The user chose the "All accounts" search.
    public private(set) var unifiedSearch = false
    /// The directory file does not load: only the primary account is open (spec 4).
    public private(set) var directoryUnreadable = false
    /// Bumped on every switch, add, remove or rename.
    public private(set) var revision = 0

    public let primary: VaultSession
    @ObservationIgnored public let store: AccountDirectoryStore
    @ObservationIgnored private let makeEnvironment: EnvironmentFactory
    @ObservationIgnored private let settingsDefaults: UserDefaults
    /// Whether a server can hold a managed account of this kind (none in this version).
    @ObservationIgnored public var serverAvailable: (FfiAccountKind) -> Bool = { _ in false }
    /// Told each time a session of an added account is made (the app plugs its sync).
    @ObservationIgnored public var sessionCreated: ((String, VaultSession) -> Void)?
    /// Told before an added account's session is dropped (the app stops its sync).
    @ObservationIgnored public var sessionRemoved: ((String) -> Void)?
    @ObservationIgnored private var sessions: [String: VaultSession] = [:]

    private nonisolated static let log = Logger(subsystem: "me.somalabs.onepass", category: "accounts")

    /// `defaults`: the suite of the primary account's settings, where added accounts get their scope.
    public init(
        store: AccountDirectoryStore, primary: VaultSession, defaults: UserDefaults,
        makeEnvironment: @escaping EnvironmentFactory
    ) {
        self.store = store
        self.primary = primary
        settingsDefaults = defaults
        self.makeEnvironment = makeEnvironment
        sessions[AccountDirectoryStore.primarySlot] = primary
        reloadDirectory()
    }

    // MARK: - Reading

    public var active: VaultSession { session(for: activeSlot) ?? primary }
    public var activeProfile: AccountProfile? { profile(activeSlot) }
    public var hasSeveralAccounts: Bool { profiles.count > 1 }

    public func profile(_ slot: String) -> AccountProfile? { profiles.first { $0.slot == slot } }

    /// The session of `slot`, made on first use. Nil for a slot not in the directory.
    public func session(for slot: String) -> VaultSession? {
        if let existing = sessions[slot] { return existing }
        guard profile(slot) != nil, slot != AccountDirectoryStore.primarySlot else { return nil }
        do {
            let url = try store.databaseURL(slot: slot)
            try Self.prepareFolder(url.deletingLastPathComponent())
            let settings = VaultSettings(defaults: settingsDefaults, scope: slot)
            let session = VaultSession(environment: makeEnvironment(slot, url, settings))
            do {
                try store.checkBinding(slot: slot)
            } catch {
                // A store that holds another account than the one bound to the slot (M4).
                session.refuseStore(.other(String(
                    localized: "accounts.error.storeMismatch", bundle: VaultKitStrings.bundle)))
            }
            sessions[slot] = session
            sessionCreated?(slot, session)
            return session
        } catch {
            Self.log.error("account session not made")
            return nil
        }
    }

    /// The session of `slot` if it was already made (views read this one: drawing a list of accounts
    /// opens no store).
    public func madeSession(_ slot: String) -> VaultSession? { sessions[slot] }

    /// Every session already made, primary first, in display order.
    public var openSessions: [(profile: AccountProfile, session: VaultSession)] {
        profiles.compactMap { p in sessions[p.slot].map { (p, $0) } }
    }

    /// At least one account is unlocked.
    public var anyUnlocked: Bool { sessions.values.contains { $0.state == .unlocked } }

    /// The sessions of the accounts that are unlocked now.
    public var unlockedProfiles: [AccountProfile] {
        openSessions.filter { $0.session.state == .unlocked }.map(\.profile)
    }

    // MARK: - Switching and locking

    /// Shows another account. The previous one keeps its own lock delay (ruling P13).
    public func switchTo(_ slot: String) throws(AccountsError) {
        guard slot != activeSlot else { return }
        guard profile(slot) != nil, session(for: slot) != nil else {
            throw .directory(.notFound)
        }
        do {
            try store.setActive(slot: slot)
        } catch {
            // The switch still happens for this launch; only the next launch's choice is lost.
            Self.log.error("active account not saved")
        }
        activeSlot = slot
        revision &+= 1
    }

    public func lock(_ slot: String) {
        sessions[slot]?.lock()
    }

    /// Every account, the hidden ones included ("Tout verrouiller", the Lock Control, Siri).
    public func lockAll() {
        for session in sessions.values { session.lock() }
    }

    /// Forwards a scene phase to every account (each applies its own delay).
    public func scenePhaseChanged(_ phase: ScenePhaseKind) {
        for session in sessions.values { session.scenePhaseChanged(phase) }
    }

    public func checkAutoLock() {
        for session in sessions.values { session.checkAutoLock() }
    }

    // MARK: - Adding

    /// Makes a slot and its empty session (`noAccount`) for the sign up or sign in that follows. A managed
    /// account is refused while no server can hold it.
    public func beginAdding(kind: FfiAccountKind, label: String, color: FfiAccountColor) throws(AccountsError)
        -> String
    {
        if case .managed = kind, !serverAvailable(kind) { throw .serverUnavailable }
        let slot: String
        do {
            slot = try store.add(kind: kind, label: label, color: color)
        } catch {
            throw .directory(VaultError(error))
        }
        reloadDirectory()
        guard session(for: slot) != nil else {
            try? store.remove(slot: slot)
            reloadDirectory()
            throw .directory(.notFound)
        }
        return slot
    }

    /// The sign up or sign in of `slot` ended unlocked: binds its account id (M4, M5). An account that is
    /// already on this device elsewhere is refused and its new slot taken out.
    public func finishAdding(_ slot: String) throws(AccountsError) {
        guard let session = sessions[slot], let accountID = session.environment.settings.accountID else {
            throw .directory(.notFound)
        }
        if let profile = profile(slot), profile.accountID == accountID { return }
        do {
            try store.bind(slot: slot, accountID: accountID)
        } catch OnePassError.Conflict {
            if slot != AccountDirectoryStore.primarySlot { discard(slot, accountID: nil) }
            throw .alreadyOnDevice
        } catch {
            throw .directory(VaultError(error))
        }
        reloadDirectory()
    }

    /// Binds the account of `slot` once it is unlocked, if it is not bound yet (the primary account of a
    /// device that had it before this version).
    public func bindIfNeeded(_ slot: String) {
        guard let profile = profile(slot), profile.accountID == nil,
            let accountID = sessions[slot]?.environment.settings.accountID
        else { return }
        if (try? store.bind(slot: slot, accountID: accountID)) != nil { reloadDirectory() }
    }

    /// The user left the sign up or sign in of a new slot: the slot, its folder and its settings go.
    public func cancelAdding(_ slot: String) {
        guard slot != AccountDirectoryStore.primarySlot, profile(slot)?.accountID == nil else { return }
        discard(slot, accountID: sessions[slot]?.environment.settings.accountID)
    }

    // MARK: - Editing

    public func update(_ slot: String, label: String, color: FfiAccountColor, workDomains: [String])
        throws(AccountsError)
    {
        do {
            try store.update(slot: slot, label: label, color: color, workDomains: workDomains)
        } catch {
            throw .directory(VaultError(error))
        }
        reloadDirectory()
    }

    public func move(_ slot: String, to index: Int) throws(AccountsError) {
        do {
            try store.reorder(slot: slot, index: index)
        } catch {
            throw .directory(VaultError(error))
        }
        reloadDirectory()
    }

    public func setUnifiedSearch(_ enabled: Bool) throws(AccountsError) {
        do {
            try store.setUnifiedSearch(enabled)
        } catch {
            throw .directory(VaultError(error))
        }
        reloadDirectory()
    }

    /// Takes an added account off this device (M8): locks it, erases its store, its settings, its Secret
    /// Key and its biometric unlock here. Nothing changes in iCloud or on the other devices, nor for any
    /// other account.
    public func remove(_ slot: String) throws(AccountsError) {
        guard slot != AccountDirectoryStore.primarySlot else { throw .primaryAccount }
        guard let profile = profile(slot) else { throw .directory(.notFound) }
        let accountID = profile.accountID ?? sessions[slot]?.environment.settings.accountID
        discard(slot, accountID: accountID)
    }

    private func discard(_ slot: String, accountID: String?) {
        let session = sessions[slot]
        session?.lock()
        if let session, let accountID {
            let environment = session.environment
            try? SecretKeyVault(keychain: environment.keychain).remove(accountID: accountID)
            environment.biometrics.disable(accountID: accountID)
        }
        session?.environment.settings.removeAll()
        sessionRemoved?(slot)
        sessions[slot] = nil
        if let folder = try? store.slotFolder(slot: slot) {
            try? FileManager.default.removeItem(at: folder)
        }
        do {
            try store.remove(slot: slot)
        } catch {
            Self.log.error("account not removed from the directory")
        }
        if activeSlot == slot { activeSlot = AccountDirectoryStore.primarySlot }
        reloadDirectory()
    }

    // MARK: - AutoFill and search

    /// The account AutoFill uses for `host` (spec 8): the one that claims the domain, else the primary.
    public func route(host: String) -> String {
        store.route(host: host)
    }

    /// The "All accounts" search (spec 7, ruling P4): empty unless the user chose it; only unlocked
    /// accounts; each result names its account.
    public func unifiedResults(query: String, sort: ItemSort = .title) -> [UnifiedResult] {
        guard unifiedSearch else { return [] }
        return openSessions
            .filter { $0.session.state == .unlocked }
            .flatMap { entry in
                entry.session.items(filter: .all, query: query, sort: sort)
                    .filter { !$0.archived && $0.trashedAt == nil }
                    .map { UnifiedResult(account: entry.profile, summary: $0) }
            }
    }

    // MARK: - Directory

    /// Re-reads the directory. A file that does not load leaves the primary account alone.
    public func reloadDirectory() {
        do {
            let directory = try store.load()
            profiles = directory.entries.map(AccountProfile.init)
            unifiedSearch = directory.unifiedSearch
            directoryUnreadable = false
            if profile(activeSlot) == nil || activeSlot != directory.active && revision == 0 {
                activeSlot = profile(directory.active) != nil ? directory.active : AccountDirectoryStore.primarySlot
            }
        } catch {
            Self.log.error("account directory unreadable, primary account only")
            profiles = [AccountProfile(FfiAccountEntry(
                slot: AccountDirectoryStore.primarySlot, accountId: nil, kind: .personal, label: "",
                color: .blue, workDomains: [], createdAt: 0))]
            unifiedSearch = false
            directoryUnreadable = true
            activeSlot = AccountDirectoryStore.primarySlot
        }
        // Sessions of slots that left the directory (another process removed them) are dropped.
        for slot in sessions.keys where slot != AccountDirectoryStore.primarySlot && profile(slot) == nil {
            sessions[slot]?.lock()
            sessionRemoved?(slot)
            sessions[slot] = nil
        }
        revision &+= 1
    }

    /// The folder of an added account's store, protected until first unlock on iOS like the primary one.
    nonisolated static func prepareFolder(_ folder: URL) throws {
        var attributes: [FileAttributeKey: Any] = [:]
        #if os(iOS) || os(visionOS)
        attributes[.protectionKey] = FileProtectionType.completeUntilFirstUserAuthentication
        #endif
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: attributes)
    }
}
