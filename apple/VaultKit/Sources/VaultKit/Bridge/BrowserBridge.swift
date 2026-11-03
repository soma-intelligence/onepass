#if os(macOS)
import AppKit
import Foundation
import OnePassCore
import os

/// The production bridge of the Mac app (spec 2026-10-27-release-bridge-design): the Safari
/// extension and the Chrome and Firefox relay reach the vault the user unlocked here, over
/// `bridge.sock` in the App Group container. The Rust `BridgeServer` checks each client's code
/// signature and runs the bridge protocol; this class shows pairing requests, keeps the pairings in
/// the keychain, confirms `reprompt` items with Touch ID and follows the session (a lock here locks
/// the bridge). Safari and known signed browsers pair without a code (spec
/// 2026-11-02-browser-auto-pairing); this class also writes the browsers' native messaging
/// manifests and keeps the user's revocations.
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

    @ObservationIgnored private let session: VaultSession
    @ObservationIgnored private let store: BridgePairingStore
    @ObservationIgnored private let container: SharedContainer
    @ObservationIgnored private var server: BridgeServer?

    /// Info.plist key: Chrome and Firefox extension ids the app serves (Safari always is).
    public static let allowedExtensionsKey = "OnePassBrowserExtensions"

    public init(
        session: VaultSession, container: SharedContainer = .resolve(),
        keychain: (any KeychainStore)? = nil
    ) {
        self.session = session
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
        let audit = container.databaseFolder.appendingPathComponent("bridge-audit.jsonl").path
        let delegate = Delegate(owner: self, store: store)
        let server = BridgeServer(
            delegate: delegate, pairings: store.load(), allowedExtensions: allowed, auditPath: audit)
        do {
            try server.start(groupContainer: container.root.path)
        } catch {
            return
        }
        server.setBlockedAuto(extensionIds: store.blockedAuto())
        self.server = server
        isRunning = true
        refreshManifests(bundle: bundle, allowed: allowed)
        session.coreSessionChanged = { [weak self] core in self?.sessionChanged(core) }
        session.hiddenVaultsChanged = { [weak self] ids in self?.excluded(ids) }
        excluded(session.hiddenVaultIDs)
        refreshPaired()
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
        isRunning = false
        requests = []
    }

    /// False when "Approuver" would be refused: the vault is locked or Touch ID is off in OnePass.
    /// The pairing sheet says so before the user tries.
    public var canApprove: Bool {
        session.state == .unlocked && session.canUseBiometrics
    }

    /// "Approuver": Touch ID (or the watch) on an unlocked vault, then the code is accepted.
    /// Without biometrics, or locked, the pairing is refused: the user unlocks, enrolls and retries.
    public func approve(_ id: UInt64) async {
        guard let request = requests.first(where: { $0.id == id }) else { return }
        let prompt = String(
            localized: "bridge.pairWithOnepass \(request.browser)", bundle: VaultKitStrings.bundle)
        let ok = await session.confirmUserPresence(prompt: prompt)
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

    // MARK: - From the bridge threads (through `Delegate`)

    func sessionChanged(_ core: Session?) {
        server?.setSession(session: core, accountName: "OnePass")
    }

    private func excluded(_ ids: Set<String>) {
        try? server?.setExcludedVaults(vaultIds: ids.sorted())
    }

    fileprivate func show(_ r: FfiBridgePairingRequest) {
        BridgeLog.note("pairing request shown")
        requests.removeAll { $0.id == r.requestId }
        requests.append(
            Request(id: r.requestId, extensionName: r.extName, browser: r.browser, code: r.code))
        // The code must be on screen while the extension shows it.
        NotificationCenter.default.post(name: Self.unlockRequestedNotification, object: nil)
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

    fileprivate func wroteVault() async {
        await session.bridgeWroteVault()
    }

    fileprivate func unlockRequested() {
        NotificationCenter.default.post(name: Self.unlockRequestedNotification, object: nil)
    }

    fileprivate func confirmReprompt() async -> Bool {
        let prompt = String(localized: "bridge.fillProtectedItem", bundle: VaultKitStrings.bundle)
        return await session.confirmUserPresence(prompt: prompt)
    }

    /// Called on Rust bridge threads; every UI step hops to the main actor.
    private final class Delegate: BridgeDelegate, @unchecked Sendable {
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

        func unlockRequested() {
            Task { @MainActor [weak owner] in owner?.unlockRequested() }
        }

        /// Blocks this bridge thread (never the main one) until Touch ID answers, at most 2 min.
        func confirmReprompt(vaultId: String, itemId: String) -> Bool {
            let done = DispatchSemaphore(value: 0)
            let answer = Answer()
            Task { @MainActor [weak owner] in
                answer.value = await owner?.confirmReprompt() ?? false
                done.signal()
            }
            guard done.wait(timeout: .now() + 120) == .success else { return false }
            return answer.value
        }

        func vaultChanged() {
            Task { @MainActor [weak owner] in await owner?.wroteVault() }
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
    /// Posted when an extension asks to unlock or to pair: the app activates its window.
    public static let unlockRequestedNotification = Notification.Name("me.somalabs.onepass.bridge.unlock")

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
