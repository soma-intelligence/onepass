import Foundation
import Synchronization

/// One version of the icon a person chose for an item. A new icon gets a new `iconID`, so it is a
/// new key: the old picture is never shown for it.
public struct CustomIconKey: Hashable, Sendable {
    public let vaultID: String
    public let itemID: String
    public let iconID: String

    /// Nil when the item has no chosen icon (`iconID` nil or empty).
    public init?(vaultID: String, itemID: String, iconID: String?) {
        guard let iconID, !iconID.isEmpty else { return nil }
        self.vaultID = vaultID
        self.itemID = itemID
        self.iconID = iconID
    }

    /// The chosen icon of a list row.
    public init?(_ summary: FfiItemSummary) {
        self.init(vaultID: summary.vaultId, itemID: summary.id, iconID: summary.customIconId)
    }

    /// The chosen icon of an open item (detail, editor draft).
    public init?(_ item: FfiItem) {
        self.init(vaultID: item.vaultId, itemID: item.id, iconID: item.customIconId)
    }
}

/// The icons people chose for their items, decrypted from the vault and kept in memory only.
///
/// - At most `capacity` icons; the least recently used one leaves first.
/// - A load that fails (not synced yet, damaged, deleted) marks its key failed for `retryDelay`:
///   rows show the automatic icon meanwhile and nothing asks the vault again in a loop. A load that
///   throws `CancellationError` ("not now": the vault is locked) is not a failure.
/// - Two prefetches of one key while it loads share the same load.
/// - `removeAll()` (the vault locked, another account shown, the app in the background) forgets
///   every icon and failure; a load still running then keeps nothing and marks nothing failed.
public final class CustomIconStore: Sendable {
    public static let capacity = 256
    public static let retryDelay: Duration = .seconds(600)

    public typealias Load = @Sendable (CustomIconKey) async throws -> Data

    private struct State {
        var icons: [CustomIconKey: Data] = [:]
        /// Least recently used first.
        var order: [CustomIconKey] = []
        var failedAt: [CustomIconKey: ContinuousClock.Instant] = [:]
        var loading: [CustomIconKey: Task<Void, Never>] = [:]
        var generation = 0

        mutating func touch(_ key: CustomIconKey) {
            if let index = order.firstIndex(of: key) { order.remove(at: index) }
            order.append(key)
        }
    }

    private let load: Load
    private let now: @Sendable () -> ContinuousClock.Instant
    private let capacity: Int
    private let state = Mutex(State())

    public init(
        capacity: Int = CustomIconStore.capacity,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now },
        load: @escaping Load
    ) {
        self.capacity = max(1, capacity)
        self.now = now
        self.load = load
    }

    /// The icon if it is in memory, without waiting.
    public func cached(_ key: CustomIconKey) -> Data? {
        state.withLock { state in
            guard let data = state.icons[key] else { return nil }
            state.touch(key)
            return data
        }
    }

    /// Loads the icon into memory unless it is there, already loading, or failed less than
    /// `retryDelay` ago. Returns once it is settled (loaded, failed or skipped).
    public func prefetch(_ key: CustomIconKey) async {
        let instant = now()
        let task: Task<Void, Never>? = state.withLock { state in
            if state.icons[key] != nil { return nil }
            if let failed = state.failedAt[key], instant - failed < Self.retryDelay { return nil }
            if let running = state.loading[key] { return running }
            let generation = state.generation
            let task = Task { await self.run(key, generation: generation) }
            state.loading[key] = task
            return task
        }
        await task?.value
    }

    /// Forgets every icon and failure (the vault locked or another account opened).
    public func removeAll() {
        state.withLock { state in
            state.icons = [:]
            state.order = []
            state.failedAt = [:]
            state.loading = [:]
            state.generation &+= 1
        }
    }

    private func run(_ key: CustomIconKey, generation: Int) async {
        var data: Data?
        var failed = false
        do {
            let loaded = try await load(key)
            if loaded.isEmpty { failed = true } else { data = loaded }
        } catch is CancellationError {
            failed = false
        } catch {
            failed = true
        }
        let instant = now()
        state.withLock { state in
            guard state.generation == generation else { return }
            state.loading[key] = nil
            if let data {
                state.icons[key] = data
                state.touch(key)
                while state.order.count > capacity {
                    state.icons[state.order.removeFirst()] = nil
                }
            } else if failed {
                // Expired marks go first, so the failures kept stay bounded too.
                if state.failedAt.count >= capacity {
                    state.failedAt = state.failedAt.filter { instant - $0.value < Self.retryDelay }
                }
                state.failedAt[key] = instant
            }
        }
    }
}

extension CustomIconStore {
    /// The store of an app or extension: icons read from the vault `session()` returns now (the
    /// account shown). A locked vault is "not now", never a failure. An extension, with its
    /// tighter memory, passes a smaller `capacity`.
    public static func vault(
        _ session: @escaping @MainActor () -> VaultSession, capacity: Int = CustomIconStore.capacity
    ) -> CustomIconStore {
        CustomIconStore(capacity: capacity) { @MainActor key in
            do {
                return try await session().customIconData(itemID: key.itemID, vaultID: key.vaultID)
            } catch VaultError.passwordRequired {
                throw CancellationError()
            }
        }
    }
}
