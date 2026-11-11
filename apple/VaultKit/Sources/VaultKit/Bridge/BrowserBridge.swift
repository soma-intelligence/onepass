#if os(macOS)
import AppKit
import Foundation
import Observation
import OnePassCore
import os

/// The production bridge of the Mac app (spec 2026-10-27-release-bridge-design): the Safari
/// extension and the Chrome and Firefox relay reach the vault the user unlocked here, over
/// `bridge.sock` in the App Group container. The Rust `BridgeServer` checks each client's code
/// signature and runs the bridge protocol; this class shows pairing requests, keeps the pairings in
/// the keychain, confirms `reprompt` items with Touch ID and follows the session (a lock here locks
/// the bridge). Safari and known signed browsers pair without a code (spec
/// 2026-11-02-browser-auto-pairing); this class also writes the browsers' native messaging
/// manifests and keeps the user's revocations. A secret served to a browser counts as use of the
/// vault, for `fillWindow` at most after the user was last in the app, and the biometric unlock a
/// browser asked for answers one `reprompt` check of that browser for that site
/// (`BridgeUnlockCredit`).
///
/// Several accounts on this Mac (ruling C, 2026-11-10): the bridge is told the primary account and
/// each added account the user made available in browsers, with its session while it is unlocked
/// and none while it is locked. The lock state the browsers see is the primary account's; a locked
/// added account gives nothing and asks nothing.
@MainActor
@Observable
public final class BrowserBridge {
    /// A pairing waiting for the user: compare the code with the one the extension shows.
    public struct Request: Identifiable, Equatable, Sendable {
        public let id: UInt64
        /// Self-declared by the extension: shown as such, never trusted.
        public let extensionName: String
        public let browser: String
        public let code: String
    }

    /// A browser paired with this Mac, without its key.
    public struct Paired: Identifiable, Equatable, Sendable {
        public let id: String
        public let extensionName: String
        /// The browser verified by code signature for an automatic pairing, else what the
        /// extension said about itself.
        public let browser: String
        /// True when the app paired it without a code, on the browser's code signature.
        public let automatic: Bool
        public let createdAt: Date
        public let lastUsed: Date
    }

    public private(set) var requests: [Request] = []
    public private(set) var paired: [Paired] = []
    /// Extension ids the user forgot: they pair again only with the code, or after "allow again".
    public private(set) var blocked: [String] = []
    /// False when this build cannot serve (unsigned, no App Group container) or the socket is
    /// taken by another running copy of the app.
    public private(set) var isRunning = false

    /// What an extension asks of the app's window.
    public enum Attention: Sendable, Equatable {
        /// A pairing code to compare: the window comes forward and stays.
        case pairing
        /// "Déverrouiller dans OnePass": the lock screen comes forward, then the browser again.
        case unlock
    }

    /// Called on the main actor when an extension asks to pair or to unlock. A request that comes
    /// before the app listens (a browser already waiting when the app launches) is kept and
    /// delivered when this is set.
    @ObservationIgnored public var attentionRequested: ((Attention) -> Void)? {
        didSet {
            guard let attentionRequested, let waiting = waitingAttention else { return }
            waitingAttention = nil
            attentionRequested(waiting)
        }
    }
    @ObservationIgnored private var waitingAttention: Attention?

    /// Set by the app around the lock screen's biometric check of the primary account: an unlock of
    /// it that lands meanwhile is the biometric one (`BridgeUnlockCredit`), any other is not.
    @ObservationIgnored public var biometricUnlockRunning = false

    /// One account as last told to the bridge (no session, no key: tests and diagnosis).
    struct Published: Equatable, Sendable {
        let slot: String
        let name: String
        let unlocked: Bool
        let excluded: [String]
    }

    /// The accounts the bridge serves now, primary first. Empty before the start, and when the
    /// bridge refused the list (everything is then locked for the browsers).
    @ObservationIgnored private(set) var published: [Published] = []

    /// The primary account's session: the one whose lock the browsers see, and that approves pairings.
    @ObservationIgnored private let session: VaultSession
    /// Every account of this Mac; nil serves the one session alone.
    @ObservationIgnored private let accounts: AccountSessions?
    @ObservationIgnored private let store: BridgePairingStore
    @ObservationIgnored private let container: SharedContainer
    @ObservationIgnored private var server: BridgeServer?
    @ObservationIgnored private var credit = BridgeUnlockCredit()
    /// Per account (slot): when it was unlocked or the user was last in the app with it on screen,
    /// whichever is later. Served fills keep an account open only `fillWindow` past this.
    @ObservationIgnored private var present: [String: Date] = [:]

    /// How long after the last unlock, or the last time the user was in the app, the fills served to
    /// the browsers still restart an account's idle delay. Past it they no longer do, so a paired
    /// client that keeps asking cannot hold a vault open for ever.
    public static let fillWindow: TimeInterval = 12 * 60 * 60

    /// Info.plist key: Chrome and Firefox extension ids the app serves (Safari always is).
    public static let allowedExtensionsKey = "OnePassBrowserExtensions"

    /// `session`: the primary account. `accounts`: every account of this Mac, whose unlocked ones the
    /// browsers reach too; nil (or a single account) serves `session` alone, as before.
    public init(
        session: VaultSession, accounts: AccountSessions? = nil, container: SharedContainer = .resolve(),
        keychain: (any KeychainStore)? = nil
    ) {
        self.session = session
        self.accounts = accounts
        self.container = container
        let keychain =
            keychain
            ?? SystemKeychain(
                service: BridgePairingStore.service, accessGroup: VaultEnvironment.sharedAccessGroup())
        self.store = BridgePairingStore(keychain: keychain)
    }

    /// Start listening when the build can: signed by a team, with its App Group container.
    /// Idempotent. Failures leave `isRunning` false and the extensions say the app is unreachable.
    public func start(bundle: Bundle = .main) {
        guard server == nil, container.isShared else { return }
        let allowed = Self.allowedExtensions(bundle.object(forInfoDictionaryKey: Self.allowedExtensionsKey))
        let journal = container.databaseFolder.appendingPathComponent("bridge-audit.jsonl")
        let server = makeServer(allowed: allowed, journal: journal)
        do {
            try server.start(groupContainer: container.root.path)
        } catch {
            return
        }
        adopt(server)
        isRunning = true
        refreshManifests(bundle: bundle, allowed: allowed)
        refreshPaired()
    }

    /// The bridge of this app, not listening yet.
    func makeServer(allowed: [String], journal: URL) -> BridgeServer {
        BridgeServer(
            delegate: Delegate(owner: self, store: store), pairings: store.load(),
            allowedExtensions: allowed, auditPath: journal.path)
    }

    /// Serves `server`: the accounts are told to it now and at each of their changes. `start` calls
    /// it once the socket listens; tests call it on a server that does not.
    func adopt(_ server: BridgeServer) {
        server.setBlockedAuto(extensionIds: store.blockedAuto())
        // Pages are routed to the account that claims their domain, as system AutoFill does.
        server.setRoutingFolder(folder: accounts?.store.folder.path)
        self.server = server
        // "Disponible dans les navigateurs" turned on or off: told in the same turn.
        accounts?.browserAvailabilityChanged = { [weak self] in self?.publish() }
        publish()
        watchAccounts()
    }

    /// An account was added, removed, renamed, or its session was just made: the bridge is told
    /// again. Also called by itself on every directory change, unlock, lock and hidden vault.
    public func accountsChanged() {
        publish()
    }

    /// The user is in the app, or just left it, with the account in `slot` on screen: its served
    /// fills count as use for `fillWindow` from now.
    public func userPresent(slot: String) {
        guard let vault = vault(slot), vault.state == .unlocked else { return }
        present[slot] = vault.environment.clock.now
    }

    /// The Info.plist value: ids separated by spaces or commas (a build setting), or an array.
    nonisolated static func allowedExtensions(_ value: Any?) -> [String] {
        let raw: [String] =
            if let list = value as? [String] { list }
            else if let text = value as? String {
                text.split(whereSeparator: { $0 == " " || $0 == "," }).map(String.init)
            } else { [] }
        return raw.map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.contains("$(") }
    }

    public func stop() {
        server?.stop()
        server?.setSession(session: nil, accountName: "")
        server = nil
        published = []
        present = [:]
        isRunning = false
        requests = []
    }

    /// False when "Approuver" would be refused: the vault is locked or Touch ID is off in OnePass.
    /// The pairing sheet says so before the user tries.
    public var canApprove: Bool {
        session.state == .unlocked && session.canUseBiometrics
    }

    /// "Approuver": Touch ID (or the watch) on an unlocked vault, then the code is accepted.
    /// Touch ID refused or cancelled: the pairing is refused. Locked or Touch ID off (when the tap
    /// comes, or by the time the check answers): nothing is answered, the request waits on its sheet
    /// for the user to unlock or enroll, until the extension gives up.
    public func approve(_ id: UInt64) async {
        guard let request = requests.first(where: { $0.id == id }) else { return }
        guard canApprove else { return }
        let prompt = String(
            localized: "bridge.pairWithOnepass \(request.browser)", bundle: VaultKitStrings.bundle)
        let ok = await session.confirmUserPresence(prompt: prompt)
        if !ok, session.state != .unlocked {
            // A lock during the check (sleep, the idle delay) is not the user's refusal.
            BridgeLog.note("pairing approval interrupted by a lock")
            return
        }
        BridgeLog.note(ok ? "pairing approved" : "pairing refused: no user presence (locked or Touch ID off)")
        server?.answerPairing(requestId: id, approved: ok)
        requests.removeAll { $0.id == id }
    }

    public func refuse(_ id: UInt64) {
        server?.answerPairing(requestId: id, approved: false)
        requests.removeAll { $0.id == id }
    }

    /// Forget a paired browser: its next connection must pair again, and with the code (a forgotten
    /// extension never pairs itself back automatically until a code pairing or `allowAgain`).
    public func forget(_ id: String) {
        server?.forgetPairing(pairingId: id)
        store.forget(id)
        server?.setBlockedAuto(extensionIds: store.blockedAuto())
        refreshPaired()
    }

    /// Lets a forgotten extension pair automatically again.
    public func allowAgain(_ extensionId: String) {
        store.allowAuto(extensionId)
        server?.setBlockedAuto(extensionIds: store.blockedAuto())
        refreshPaired()
    }

    /// Write or refresh the native messaging manifests of the installed browsers, so that Chrome,
    /// Edge, Brave and Firefox find `onepass-relay` with no step from the user. Called at start and
    /// whenever the app comes forward. Never throws: a browser whose folder is missing waits.
    public func refreshManifests(bundle: Bundle = .main) {
        refreshManifests(
            bundle: bundle,
            allowed: Self.allowedExtensions(bundle.object(forInfoDictionaryKey: Self.allowedExtensionsKey)))
    }

    private func refreshManifests(bundle: Bundle, allowed: [String]) {
        guard let home = NativeMessagingManifests.userHome() else { return }
        let relay = bundle.bundleURL.appendingPathComponent("Contents/Helpers/onepass-relay")
        let written = NativeMessagingManifests.install(
            home: home, relay: relay, extensionIDs: allowed,
            isInstalled: { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil })
        if !written.isEmpty { BridgeLog.note("native messaging manifests written: \(written.count)") }
    }

    // MARK: - Accounts

    private static let primarySlot = AccountDirectoryStore.primarySlot

    private struct Served {
        let slot: String
        let name: String
        /// Nil for an added account whose session was not made this launch (it is locked).
        let vault: VaultSession?
    }

    /// The accounts the browsers may reach, primary first: the primary one, and each added account
    /// that is signed in (bound to its store) and that the user made available in browsers (off by
    /// default: a paired browser reads every account listed here). One account: its name stays
    /// "OnePass", as before.
    private func roster() -> [Served] {
        guard let accounts, accounts.hasSeveralAccounts else {
            return [Served(slot: Self.primarySlot, name: "OnePass", vault: session)]
        }
        return accounts.profiles.compactMap { profile in
            if profile.isPrimary {
                return Served(slot: profile.slot, name: Self.name(profile, session), vault: session)
            }
            guard profile.accountID != nil, accounts.isAvailableInBrowsers(profile.slot) else { return nil }
            let vault = accounts.madeSession(profile.slot)
            return Served(slot: profile.slot, name: Self.name(profile, vault), vault: vault)
        }
    }

    /// The account's label, else its profile name (the primary account has no label until named).
    private static func name(_ profile: AccountProfile, _ vault: VaultSession?) -> String {
        if !profile.label.isEmpty { return profile.label }
        let shown = vault?.environment.settings.displayName ?? ""
        return shown.isEmpty ? "OnePass" : shown
    }

    /// The session of the account in `slot`, if it was made.
    private func vault(_ slot: String) -> VaultSession? {
        if slot == Self.primarySlot { return session }
        return accounts?.madeSession(slot)
    }

    /// Tells the bridge every account: its session while unlocked, none while locked, and the vaults
    /// it hides. Each session made so far reports its unlocks, locks and hidden vaults here at once
    /// (a lock drops the session from the bridge in the same turn).
    private func publish() {
        guard let server else { return }
        let roster = roster()
        var list: [FfiBridgeAccount] = []
        var told: [Published] = []
        for account in roster {
            if let vault = account.vault { follow(vault, slot: account.slot) }
            let core = account.vault?.coreSession
            // First seen unlocked (it was before the bridge started): its window starts here.
            if core != nil, present[account.slot] == nil, let vault = account.vault {
                present[account.slot] = vault.environment.clock.now
            }
            let hidden = (account.vault?.hiddenVaultIDs ?? []).sorted()
            list.append(
                FfiBridgeAccount(
                    slot: account.slot, session: core, accountName: account.name, excludedVaultIds: hidden))
            told.append(Published(slot: account.slot, name: account.name, unlocked: core != nil, excluded: hidden))
        }
        do {
            try server.setSessions(accounts: list)
            published = told
        } catch {
            // Refused whole (a slot or a vault id it cannot read), the previous list kept: nothing
            // stale may stay served, so the browsers see a locked app.
            server.setSession(session: nil, accountName: "")
            published = []
            BridgeLog.note("accounts refused by the bridge: locked for the browsers")
        }
    }

    private func follow(_ vault: VaultSession, slot: String) {
        vault.coreSessionChanged = { [weak self] core in self?.sessionChanged(slot, core) }
        vault.hiddenVaultsChanged = { [weak self] _ in self?.publish() }
    }

    /// The directory changed (an account added, removed, renamed, reordered, switched to).
    private func watchAccounts() {
        guard let accounts else { return }
        withObservationTracking {
            _ = accounts.revision
        } onChange: { [weak self] in
            Task { @MainActor in
                guard let self, self.server != nil else { return }
                self.publish()
                self.watchAccounts()
            }
        }
    }

    // MARK: - From the bridge threads (through `Delegate`)

    /// The account in `slot` unlocked (`core`) or locked (nil).
    func sessionChanged(_ slot: String, _ core: Session?) {
        present[slot] = core != nil ? vault(slot)?.environment.clock.now : nil
        if slot == Self.primarySlot {
            if core != nil {
                credit.unlocked(biometric: biometricUnlockRunning, now: session.environment.clock.now)
            } else {
                credit.clear()
            }
        }
        publish()
    }

    /// The bridge released a secret of the account in `slot` to a browser, after all its checks (it
    /// says so itself, `BridgeDelegate.fillServed`): the user is at work with that vault, so its idle
    /// delay starts again. Nothing else from a browser does that (status polls, pairing, refused
    /// requests, agent fills), or a page could hold a vault open. And only for `fillWindow` after the
    /// account was unlocked or the user was last in the app: past that, the delay runs out.
    func fillServed(account slot: String = AccountDirectoryStore.primarySlot) {
        guard let vault = vault(slot), vault.state == .unlocked, let since = present[slot] else { return }
        guard vault.environment.clock.now.timeIntervalSince(since) <= Self.fillWindow else { return }
        vault.noteBrowserFill()
    }

    private func ask(_ attention: Attention) {
        if let attentionRequested { attentionRequested(attention) } else { waitingAttention = attention }
    }

    func show(_ r: FfiBridgePairingRequest) {
        BridgeLog.note("pairing request shown")
        requests.removeAll { $0.id == r.requestId }
        requests.append(
            Request(id: r.requestId, extensionName: r.extName, browser: r.browser, code: r.code))
        // The code must be on screen while the extension shows it.
        ask(.pairing)
    }

    fileprivate func ended(_ id: UInt64) {
        requests.removeAll { $0.id == id }
    }

    fileprivate func refreshPaired() {
        paired = store.load().map {
            Paired(
                id: $0.pairingId, extensionName: $0.extName,
                browser: $0.verifiedBrowser.isEmpty ? $0.browser : $0.verifiedBrowser,
                automatic: !$0.verifiedBrowser.isEmpty,
                createdAt: Date(timeIntervalSince1970: TimeInterval($0.createdAt)),
                lastUsed: Date(timeIntervalSince1970: TimeInterval($0.lastUsed)))
        }.sorted { $0.createdAt < $1.createdAt }
        blocked = store.blockedAuto()
    }

    /// The bridge wrote to the account in `slot`: that account reloads and pushes.
    func wroteVault(slot: String) async {
        await vault(slot)?.bridgeWroteVault()
    }

    /// The paired client `pairing` asked to unlock (never a pairing), for the page on `host` when it
    /// said: the app may give the front back to the browser after it (MS-03), the Touch ID that
    /// answers names that site, and a biometric unlock answers one `reprompt` check of that client
    /// for that site. The request is for the primary account, whose lock is the one the browsers see.
    func unlockRequested(pairing: String, host: String?) {
        if session.state != .unlocked {
            let now = session.environment.clock.now
            credit.unlockRequested(now: now, pairing: pairing, host: host)
            // A prompt for a site the user is not signing in to looks wrong, as it should.
            session.biometricPrompt = credit.requestedHost(now: now).map { site in
                VaultSession.BiometricPrompt(
                    text: String(localized: "session.unlockOnepassFor \(site)", bundle: VaultKitStrings.bundle),
                    until: now.addingTimeInterval(BridgeUnlockCredit.requestWindow))
            }
        }
        ask(.unlock)
    }

    /// Touch ID for an item marked `reprompt` of the account in `slot`, asked on that account's own
    /// session, for the paired client `pairing` and the page on `host` (nil: the extension's own
    /// window). An account that is locked, or unknown here, refuses.
    func confirmReprompt(slot: String, pairing: String, host: String?) async -> Bool {
        guard let vault = vault(slot) else { return false }
        // The Touch ID that just unlocked the primary vault for this browser and this site answers
        // once, for an item of that account only.
        if slot == Self.primarySlot, vault.state == .unlocked,
            credit.consume(now: vault.environment.clock.now, pairing: pairing, host: host)
        {
            BridgeLog.note("reprompt answered by the unlock")
            vault.noteActivity()
            return true
        }
        let prompt = String(localized: "bridge.fillProtectedItem", bundle: VaultKitStrings.bundle)
        return await vault.confirmUserPresence(prompt: prompt)
    }

    /// Called on Rust bridge threads; every UI step hops to the main actor.
    final class Delegate: BridgeDelegate, @unchecked Sendable {
        weak var owner: BrowserBridge?
        let store: BridgePairingStore

        init(owner: BrowserBridge, store: BridgePairingStore) {
            self.owner = owner
            self.store = store
        }

        func pairingRequested(request: FfiBridgePairingRequest) {
            Task { @MainActor [weak owner] in owner?.show(request) }
        }

        func pairingEnded(requestId: UInt64) {
            Task { @MainActor [weak owner] in owner?.ended(requestId) }
        }

        /// Persisted before the extension hears `pair_ok`. A code pairing lifts the extension's
        /// block here as it does in the core.
        func pairingStored(pairing: FfiBridgePairing) {
            store.add(pairing)
            BridgeLog.note(pairing.verifiedBrowser.isEmpty ? "pairing stored" : "pairing stored automatically")
            Task { @MainActor [weak owner] in owner?.refreshPaired() }
        }

        func pairingUsed(pairingId: String, at: UInt64) {
            store.touch(pairingId, at: at)
        }

        func unlockRequested(pairingId: String, originHost: String?) {
            Task { @MainActor [weak owner] in owner?.unlockRequested(pairing: pairingId, host: originHost) }
        }

        /// Blocks this bridge thread (never the main one) until Touch ID answers, at most 2 min.
        func confirmReprompt(
            slot: String, vaultId: String, itemId: String, pairingId: String, originHost: String?
        ) -> Bool {
            let done = DispatchSemaphore(value: 0)
            let answer = Answer()
            Task { @MainActor [weak owner] in
                answer.value =
                    await owner?.confirmReprompt(slot: slot, pairing: pairingId, host: originHost) ?? false
                done.signal()
            }
            guard done.wait(timeout: .now() + 120) == .success else { return false }
            return answer.value
        }

        /// `vaultId` is nil when several vaults of the account may have changed: the whole account
        /// reloads either way.
        func vaultChanged(slot: String, vaultId: String?) {
            Task { @MainActor [weak owner] in await owner?.wroteVault(slot: slot) }
        }

        /// A secret was served, every check passed (never a plan, a save, a refusal or an agent's).
        func fillServed(slot: String, pairingId: String, kind: String) {
            Task { @MainActor [weak owner] in owner?.fillServed(account: slot) }
        }

        func note(message: String) {
            BridgeLog.note(message)
        }
    }

    private final class Answer: @unchecked Sendable {
        var value = false
    }
}

/// Bridge journal: fixed messages only (no secret, no item data), in the unified log of every
/// build, so a refused Safari or Chrome connection can be diagnosed on a release install.
enum BridgeLog {
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "bridge")

    static func note(_ message: String) {
        log.notice("\(message, privacy: .public)")
    }
}

extension BrowserBridge {
    /// "Déverrouiller dans OnePass": opened by the Safari extension's handler and by the relay of
    /// Chrome and Firefox through LaunchServices, from the process that served the user's click.
    /// Since macOS 14 the app cannot bring itself forward while the browser is in front; a link
    /// opened for it can, and launches it when it is not running. It carries nothing.
    public static let unlockURL = URL(string: "onepass://unlock")!

    /// Exactly `onepass://unlock`: no path, query, fragment, user or port.
    public static func isUnlockLink(_ url: URL) -> Bool {
        guard url.scheme == "onepass",
            let c = URLComponents(url: url, resolvingAgainstBaseURL: false),
            c.host == "unlock", c.path.isEmpty, c.query == nil, c.fragment == nil,
            c.user == nil, c.password == nil, c.port == nil
        else { return false }
        return true
    }
}
#endif
