import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// A clock the test moves by hand.
private final class TestClock: Sendable {
    private let instant = Mutex(ContinuousClock.now)
    func now() -> ContinuousClock.Instant { instant.withLock { $0 } }
    func advance(_ duration: Duration) { instant.withLock { $0 += duration } }
}

/// Counts the loads per key and answers each with `answer`.
private final class LoadCounter: Sendable {
    private let counts = Mutex([CustomIconKey: Int]())
    let answer: @Sendable (CustomIconKey) async throws -> Data

    init(answer: @escaping @Sendable (CustomIconKey) async throws -> Data) {
        self.answer = answer
    }

    func count(_ key: CustomIconKey) -> Int { counts.withLock { $0[key, default: 0] } }
    var total: Int { counts.withLock { $0.values.reduce(0, +) } }

    func load(_ key: CustomIconKey) async throws -> Data {
        counts.withLock { $0[key, default: 0] += 1 }
        return try await answer(key)
    }
}

private func key(_ item: String = "item-1", icon: String = "icon-1") -> CustomIconKey {
    CustomIconKey(vaultID: "vault-1", itemID: item, iconID: icon)!
}

private func store(_ counter: LoadCounter, clock: TestClock = TestClock(), capacity: Int = CustomIconStore.capacity)
    -> CustomIconStore
{
    CustomIconStore(capacity: capacity, now: { clock.now() }, load: { try await counter.load($0) })
}

@Suite struct CustomIconStoreTests {
    @Test func keyNeedsAnIconID() {
        #expect(CustomIconKey(vaultID: "v", itemID: "i", iconID: nil) == nil)
        #expect(CustomIconKey(vaultID: "v", itemID: "i", iconID: "") == nil)
        #expect(CustomIconKey(vaultID: "v", itemID: "i", iconID: "a") != nil)
    }

    @Test func cachedAfterPrefetch() async {
        let counter = LoadCounter { Data("icon-\($0.itemID)".utf8) }
        let icons = store(counter)
        #expect(icons.cached(key()) == nil)
        await icons.prefetch(key())
        #expect(icons.cached(key()) == Data("icon-item-1".utf8))
        await icons.prefetch(key())
        #expect(counter.count(key()) == 1)
    }

    @Test func failedLoadNotRetriedWithin10Minutes() async {
        let clock = TestClock()
        let counter = LoadCounter { _ in throw VaultError.notFound }
        let icons = store(counter, clock: clock)
        await icons.prefetch(key())
        await icons.prefetch(key())
        #expect(counter.count(key()) == 1)
        #expect(icons.cached(key()) == nil)
        clock.advance(.seconds(599))
        await icons.prefetch(key())
        #expect(counter.count(key()) == 1)
        clock.advance(.seconds(1))
        await icons.prefetch(key())
        #expect(counter.count(key()) == 2)
    }

    @Test func newIconIDIsNewKey() async {
        let counter = LoadCounter { Data($0.iconID.utf8) }
        let icons = store(counter)
        await icons.prefetch(key(icon: "first"))
        #expect(icons.cached(key(icon: "first")) == Data("first".utf8))
        #expect(icons.cached(key(icon: "second")) == nil)
        await icons.prefetch(key(icon: "second"))
        #expect(icons.cached(key(icon: "second")) == Data("second".utf8))
        #expect(counter.total == 2)
    }

    @Test func twoPrefetchesInFlightLoadOnce() async {
        let gate = AsyncGate()
        let counter = LoadCounter { _ in
            await gate.wait()
            return Data("icon".utf8)
        }
        let icons = store(counter)
        async let first: Void = icons.prefetch(key())
        // The load has started and is held: the second prefetch finds it in flight.
        await gate.entered()
        async let second: Void = icons.prefetch(key())
        await gate.open()
        _ = await (first, second)
        #expect(counter.count(key()) == 1)
        #expect(icons.cached(key()) == Data("icon".utf8))
    }

    /// Account switch or lock while a load is pending: its answer (here NotFound, read against the
    /// other account) neither fills the cache nor marks the key failed.
    @Test func removeAllWhileLoadingDiscardsItsResult() async {
        let gate = AsyncGate()
        let counter = LoadCounter { _ in
            await gate.wait()
            throw VaultError.notFound
        }
        let icons = store(counter)
        async let pending: Void = icons.prefetch(key())
        await gate.entered()
        icons.removeAll()
        await gate.open()
        await pending
        #expect(icons.cached(key()) == nil)
        // Not marked failed: the next prefetch asks the vault again.
        await icons.prefetch(key())
        #expect(counter.count(key()) == 2)
    }

    @Test func boundedLeastRecentlyUsedLeavesFirst() async {
        let counter = LoadCounter { Data($0.itemID.utf8) }
        let icons = store(counter, capacity: 2)
        await icons.prefetch(key("a"))
        await icons.prefetch(key("b"))
        // "a" is read again: "b" is now the least recently used.
        #expect(icons.cached(key("a")) != nil)
        await icons.prefetch(key("c"))
        #expect(icons.cached(key("a")) != nil)
        #expect(icons.cached(key("b")) == nil)
        #expect(icons.cached(key("c")) != nil)
    }

    @Test func cancellationIsNotAFailure() async {
        let locked = Mutex(true)
        let counter = LoadCounter { _ in
            if locked.withLock({ $0 }) { throw CancellationError() }
            return Data("icon".utf8)
        }
        let icons = store(counter)
        await icons.prefetch(key())
        #expect(icons.cached(key()) == nil)
        locked.withLock { $0 = false }
        await icons.prefetch(key())
        #expect(icons.cached(key()) == Data("icon".utf8))
        #expect(counter.count(key()) == 2)
    }

    @Test func removeAllForgetsIconsAndFailures() async {
        let fails = Mutex(true)
        let counter = LoadCounter { key in
            if key.itemID == "bad", fails.withLock({ $0 }) { throw VaultError.notFound }
            return Data("icon".utf8)
        }
        let icons = store(counter)
        await icons.prefetch(key("good"))
        await icons.prefetch(key("bad"))
        icons.removeAll()
        #expect(icons.cached(key("good")) == nil)
        fails.withLock { $0 = false }
        await icons.prefetch(key("bad"))
        #expect(icons.cached(key("bad")) == Data("icon".utf8))
    }

    // MARK: - Resolver

    private let packIcon = Data("pack-webp".utf8)

    private func resolver(directory: URL, custom: CustomIconStore) throws -> ItemIconResolver {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let baseline = directory.appending(path: "baseline.bin")
        try makeIconPack(version: 3, icons: [(packIcon, 0)], domains: ["withings.com": 0], names: ["withings": 0])
            .write(to: baseline)
        return ItemIconResolver(
            pack: IconPackStore(baseline: baseline, directory: directory.appending(path: "pack"), publicKey: ""),
            site: SiteIconLoader(cacheDirectory: directory.appending(path: "site"), enabled: { true }),
            custom: custom, enabled: { true })
    }

    @Test func resolverPrefersCustom() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "custom-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let chosen = Data("chosen-png".utf8)
        let icons = try resolver(directory: directory, custom: store(LoadCounter { _ in chosen }))
        let url = "https://account.withings.com/login"
        // Before the load: the pack icon, on the first frame.
        #expect(icons.cachedIcon(for: url, title: "Withings", custom: key()) == packIcon)
        #expect(await icons.icon(for: url, title: "Withings", custom: key()) == chosen)
        #expect(icons.cachedIcon(for: url, title: "Withings", custom: key()) == chosen)
        // No key: the automatic icon.
        #expect(icons.cachedIcon(for: url, title: "Withings", custom: nil) == packIcon)
    }

    @Test func resolverFallsBackWhenCustomFailed() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "custom-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let clock = TestClock()
        let counter = LoadCounter { _ in throw VaultError.notFound }
        let icons = try resolver(directory: directory, custom: store(counter, clock: clock))
        let url = "https://withings.com"
        #expect(await icons.icon(for: url, title: "Withings", custom: key()) == packIcon)
        #expect(icons.cachedIcon(for: url, title: "Withings", custom: key()) == packIcon)
        #expect(await icons.icon(for: nil, title: "Withings", custom: key()) == packIcon)
        #expect(counter.count(key()) == 1)
    }

    /// Review focus: an icon not synced yet (NotFound) shows the automatic icon, and rows redrawn
    /// for 10 minutes never ask the vault again.
    @Test func notFoundFallsBackAndIsNotRetriedWithin10Minutes() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "custom-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let clock = TestClock()
        let counter = LoadCounter { _ in throw VaultError.notFound }
        let icons = try resolver(directory: directory, custom: store(counter, clock: clock))
        let url = "https://withings.com"
        for _ in 0..<5 {
            #expect(await icons.icon(for: url, title: "Withings", custom: key()) == packIcon)
            clock.advance(.seconds(60))
        }
        #expect(counter.count(key()) == 1)
        clock.advance(.seconds(300))
        _ = await icons.icon(for: url, title: "Withings", custom: key())
        #expect(counter.count(key()) == 2)
    }
}

/// Holds loads until the test opens it; `entered()` returns once a load is held.
private actor AsyncGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var held = 0
    private var enteredWaiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        held += 1
        enteredWaiters.forEach { $0.resume() }
        enteredWaiters = []
        await withCheckedContinuation { waiters.append($0) }
    }

    func entered() async {
        if held > 0 { return }
        await withCheckedContinuation { enteredWaiters.append($0) }
    }

    func open() {
        isOpen = true
        waiters.forEach { $0.resume() }
        waiters = []
    }
}
