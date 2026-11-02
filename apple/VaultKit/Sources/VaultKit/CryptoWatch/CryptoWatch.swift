import Foundation
import Observation

/// The watch of one unlocked account: its settings, the last snapshot (from the encrypted file at
/// first, then from each refresh), and the refresh itself. Refreshes run only when the Crypto
/// screen opens or the user pulls to refresh (`refresh`), never on a timer or in the background.
/// `clear` (on lock) drops everything from memory.
@MainActor
@Observable
public final class CryptoWatch {
    public enum Phase: Equatable, Sendable {
        case idle
        case refreshing
        /// The last refresh could not reach a provider: the shown values are the cached ones.
        case offline
    }

    public private(set) var settings = CryptoWatchSettings()
    public private(set) var snapshot: CryptoSnapshot?
    public private(set) var phase: Phase = .idle
    /// Wallet items with watch data, from the last `refresh` or `loadTargets`.
    public private(set) var targets: [CryptoWatchTarget] = []
    /// Raw core data of the wallets (invalid entries, phrase state) for the item screens.
    public private(set) var wallets: [FfiWalletWatch] = []

    @ObservationIgnored private var store: CryptoWatchStore?
    @ObservationIgnored private var service: CryptoWatchService
    @ObservationIgnored private var loaded = false
    @ObservationIgnored private var running: Task<Void, Never>?

    public init(service: CryptoWatchService = CryptoWatchService()) {
        self.service = service
    }

    /// Binds the watch to an account's encrypted file and reads it (settings and cached snapshot).
    public func open(store: CryptoWatchStore) {
        guard !loaded || self.store?.fileURL != store.fileURL else { return }
        self.store = store
        let state = store.load()
        settings = state.settings
        snapshot = state.settings.enabled ? state.snapshot : nil
        loaded = true
    }

    /// Replaces the service (tests, the demo's recorded provider).
    public func useService(_ service: CryptoWatchService) {
        self.service = service
    }

    public var isEnabled: Bool { settings.enabled }

    public func portfolio(period: CryptoPeriod? = nil) -> CryptoPortfolio? {
        snapshot.map { CryptoPortfolio(snapshot: $0, period: period ?? settings.period) }
    }

    /// Reads the wallet items' public watch data from the core (no network).
    public func loadTargets(from session: VaultSession) async {
        guard let all = try? await session.watchWallets() else { return }
        setWallets(all.filter { !session.hiddenVaultIDs.contains($0.vaultId) })
    }

    /// The wallets to watch (tests and the demo set them directly).
    public func setWallets(_ list: [FfiWalletWatch]) {
        wallets = list
        targets = list.map(CryptoWatchTarget.init).filter { !$0.isEmpty }
    }

    /// Changes the settings and saves them. Turning the watch off erases the cached balances.
    public func update(_ change: (inout CryptoWatchSettings) -> Void) {
        var next = settings
        change(&next)
        guard next != settings else { return }
        let currencyChanged = next.currency != settings.currency
        settings = next
        if !next.enabled {
            snapshot = nil
        } else if currencyChanged {
            snapshot?.prices = [:]
            snapshot?.charts = [:]
            snapshot?.market = []
        }
        persist()
    }

    /// One refresh of `targets` (screen open, pull to refresh). Does nothing while off. A refresh
    /// already running is awaited, not doubled.
    public func refresh() async {
        guard settings.enabled else { return }
        if let running {
            await running.value
            return
        }
        let (targets, settings, previous, service) = (targets, settings, snapshot, service)
        let task = Task {
            phase = .refreshing
            let next = await service.refresh(targets: targets, settings: settings, previous: previous)
            guard self.settings.enabled else {
                phase = .idle
                return
            }
            let failedAll = !targets.isEmpty && next.wallets.allSatisfy { w in
                let t = targets.first { $0.itemID == w.itemID }
                return w.failed.count == (t?.addresses.count ?? 0) + (t?.xpub == nil ? 0 : 1)
            }
            snapshot = next
            phase = failedAll ? .offline : .idle
            persist()
        }
        running = task
        await task.value
        running = nil
    }

    private func persist() {
        try? store?.save(CryptoWatchState(settings: settings, snapshot: snapshot))
    }

    /// Lock: forget everything held in memory (the encrypted file stays).
    public func clear() {
        running?.cancel()
        running = nil
        store = nil
        loaded = false
        settings = CryptoWatchSettings()
        snapshot = nil
        targets = []
        wallets = []
        phase = .idle
    }

    /// Items with a non-zero watched balance whose phrase has no per-item Travel Mode protection
    /// (Watchtower).
    public var unprotectedFundedWallets: [FfiWalletWatch] {
        guard let snapshot else { return [] }
        let funded = Set(snapshot.wallets.filter { $0.holdings.contains { $0.amount > 0 } }.map(\.itemID))
        return wallets.filter { $0.phraseUnprotected && funded.contains($0.itemId) }
    }
}
