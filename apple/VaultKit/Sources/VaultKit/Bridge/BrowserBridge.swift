#if os(macOS)
import Foundation
import OnePassCore

/// The production bridge of the Mac app (spec 2026-10-27-release-bridge-design): the Safari
/// extension and the Chrome and Firefox relay reach the vault the user unlocked here, over
/// `bridge.sock` in the App Group container. The Rust `BridgeServer` checks each client's code
/// signature and runs the bridge protocol; this class shows pairing requests, keeps the pairings in
/// the keychain, confirms `reprompt` items with Touch ID and follows the session (a lock here locks
/// the bridge).
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
        public let browser: String
        public let createdAt: Date
        public let lastUsed: Date
    }

    public private(set) var requests: [Request] = []
    public private(set) var paired: [Paired] = []
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
        self.server = server
        isRunning = true
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

    /// "Approuver": Touch ID (or the watch) on an unlocked vault, then the code is accepted.
    /// Without biometrics, or locked, the pairing is refused: the user unlocks, enrolls and retries.
    public func approve(_ id: UInt64) async {
        guard let request = requests.first(where: { $0.id == id }) else { return }
        let prompt = String(
            localized: "Associer \(request.browser) à OnePass", bundle: VaultKitStrings.bundle)
        let ok = await session.confirmUserPresence(prompt: prompt)
        server?.answerPairing(requestId: id, approved: ok)
        requests.removeAll { $0.id == id }
    }

    public func refuse(_ id: UInt64) {
        server?.answerPairing(requestId: id, approved: false)
        requests.removeAll { $0.id == id }
    }

    /// Forget a paired browser: its next connection must pair again.
    public func forget(_ id: String) {
        server?.forgetPairing(pairingId: id)
        store.remove(id)
        refreshPaired()
    }

    // MARK: - From the bridge threads (through `Delegate`)

    func sessionChanged(_ core: Session?) {
        server?.setSession(session: core, accountName: "OnePass")
    }

    private func excluded(_ ids: Set<String>) {
        try? server?.setExcludedVaults(vaultIds: ids.sorted())
    }

    fileprivate func show(_ r: FfiBridgePairingRequest) {
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
                id: $0.pairingId, extensionName: $0.extName, browser: $0.browser,
                createdAt: Date(timeIntervalSince1970: TimeInterval($0.createdAt)),
                lastUsed: Date(timeIntervalSince1970: TimeInterval($0.lastUsed)))
        }.sorted { $0.createdAt < $1.createdAt }
    }

    fileprivate func wroteVault() async {
        await session.bridgeWroteVault()
    }

    fileprivate func unlockRequested() {
        NotificationCenter.default.post(name: Self.unlockRequestedNotification, object: nil)
    }

    fileprivate func confirmReprompt() async -> Bool {
        let prompt = String(localized: "Remplir un élément protégé", bundle: VaultKitStrings.bundle)
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

        /// Persisted before the extension hears `pair_ok`.
        func pairingStored(pairing: FfiBridgePairing) {
            store.add(pairing)
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

/// Bridge journal: fixed messages only, in the unified log (private by default).
enum BridgeLog {
    static func note(_ message: String) {
        #if DEBUG
        NSLog("OnePass bridge: %@", message)
        #endif
    }
}

extension BrowserBridge {
    /// Posted when an extension asks to unlock or to pair: the app activates its window.
    public static let unlockRequestedNotification = Notification.Name("me.somalabs.onepass.bridge.unlock")
}

/// The pairings in one keychain item (JSON list, keys in base64), `WhenUnlockedThisDeviceOnly`,
/// never synchronized. Written from bridge threads: every read-modify-write holds the lock.
final class BridgePairingStore: @unchecked Sendable {
    static let service = "me.somalabs.onepass.bridge"
    static let key = "pairings"
    /// `last_used` is written back at most this often per pairing.
    static let touchInterval: UInt64 = 3600

    private let keychain: any KeychainStore
    private let lock = NSLock()

    init(keychain: any KeychainStore) {
        self.keychain = keychain
    }

    private struct Stored: Codable {
        var pairingId: String
        var key: String
        var extName: String
        var browser: String
        var extensionId: String
        var createdAt: UInt64
        var lastUsed: UInt64
    }

    private func read() -> [Stored] {
        guard let data = try? keychain.read(Self.key) else { return [] }
        return (try? JSONDecoder().decode([Stored].self, from: data)) ?? []
    }

    private func write(_ list: [Stored]) {
        guard let data = try? JSONEncoder().encode(list) else { return }
        try? keychain.write(Self.key, data)
    }

    func load() -> [FfiBridgePairing] {
        lock.lock()
        defer { lock.unlock() }
        return read().compactMap { s in
            guard let key = Data(base64Encoded: s.key), key.count == 32 else { return nil }
            return FfiBridgePairing(
                pairingId: s.pairingId, key: key, extName: s.extName, browser: s.browser,
                extensionId: s.extensionId, createdAt: s.createdAt, lastUsed: s.lastUsed)
        }
    }

    func add(_ p: FfiBridgePairing) {
        lock.lock()
        defer { lock.unlock() }
        var list = read().filter { $0.pairingId != p.pairingId }
        list.append(
            Stored(
                pairingId: p.pairingId, key: p.key.base64EncodedString(), extName: p.extName,
                browser: p.browser, extensionId: p.extensionId, createdAt: p.createdAt,
                lastUsed: p.lastUsed))
        write(list)
    }

    func touch(_ id: String, at: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        var list = read()
        guard let i = list.firstIndex(where: { $0.pairingId == id }),
            at >= list[i].lastUsed + Self.touchInterval
        else { return }
        list[i].lastUsed = at
        write(list)
    }

    func remove(_ id: String) {
        lock.lock()
        defer { lock.unlock() }
        let list = read()
        let kept = list.filter { $0.pairingId != id }
        if kept.count != list.count { write(kept) }
    }
}
#endif
