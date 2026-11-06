import Foundation

/// The zone round of an account (sharing spec 13.3): contact, family and shared vault mailboxes,
/// after the private round. The app talks to the Rust `ZoneSyncHandle` through
/// `FfiZoneSyncAdapter`; tests script a fake.
public protocol ZoneSyncing: Sendable {
    /// One zone round: with an unlocked `session` the share actions run too. `now`: Unix seconds.
    func runRound(session: Session?, now: Int64) async -> FfiZoneRoundReport
    /// The wake channel of every zone the last round synced, with its mailbox id.
    func wakeTopics() async -> [FfiZoneWake]
    /// Listen to one zone's wake channel; `onWake` runs on the listener's thread.
    func startWake(_ info: FfiWakeInfo, onWake: @escaping @Sendable () -> Void) async throws -> any WakeStopping
    /// This device's push target on zone mailbox `mailboxID` (hex), under `tag` (16 bytes).
    func setPushTarget(mailboxID: String, tag: Data, kind: FfiPushKind, token: Data) async throws
}

/// `ZoneSyncHandle` of the core, each call on the core thread (a round blocks on the network).
public struct FfiZoneSyncAdapter: ZoneSyncing {
    public let handle: ZoneSyncHandle
    public let store: SyncStoreHandle

    public init(handle: ZoneSyncHandle, store: SyncStoreHandle) {
        self.handle = handle
        self.store = store
    }

    public func runRound(session: Session?, now: Int64) async -> FfiZoneRoundReport {
        let (handle, store) = (handle, store)
        let report = try? await CoreThread.run { handle.runRound(session: session, store: store, now: now) }
        return report ?? FfiZoneRoundReport(
            zones: [], actionsDone: 0, refusals: [], quotaFull: [], changed: false,
            retryAfterSeconds: nil, rerun: false
        )
    }

    public func wakeTopics() async -> [FfiZoneWake] {
        let handle = handle
        return (try? await CoreThread.run { handle.wakeTopics() }) ?? []
    }

    public func startWake(_ info: FfiWakeInfo, onWake: @escaping @Sendable () -> Void) async throws -> any WakeStopping {
        let handle = try await CoreThread.run {
            try startWakeListener(info: info, observer: ZoneWakeObserver(onWake))
        }
        return ZoneWakeHandle(handle: handle)
    }

    public func setPushTarget(mailboxID: String, tag: Data, kind: FfiPushKind, token: Data) async throws {
        let handle = handle
        try await CoreThread.run {
            try handle.setPushTarget(mailboxId: mailboxID, tag: tag, kind: kind, token: token)
        }
    }
}

private final class ZoneWakeObserver: FfiWakeObserver, @unchecked Sendable {
    private let onWake: @Sendable () -> Void

    init(_ onWake: @escaping @Sendable () -> Void) {
        self.onWake = onWake
    }

    func wake() { onWake() }
}

private struct ZoneWakeHandle: WakeStopping {
    let handle: WakeListenerHandle

    func stop() { handle.stop() }
}

/// What the screens show of a zone the server refuses (spec 13.8): erased after a signed removal,
/// otherwise kept here read-only with "Le serveur refuse l'accès".
public struct ZoneRefusal: Equatable, Sendable {
    public let zone: FfiZone
    public let removed: Bool

    public init(zone: FfiZone, removed: Bool) {
        self.zone = zone
        self.removed = removed
    }
}

/// Schedules the zone rounds (spec 13.6, 13.7): one at a time, right after each private round, at
/// opening, every 15 minutes in the foreground, and on each wake of a zone's channel while in the
/// foreground. Owned by the private coordinators (`MailboxSyncCoordinator`, `SyncCoordinator`), which
/// call `afterPrivateRound`.
public actor ZoneRoundScheduler {
    public static let foregroundInterval: Duration = .seconds(15 * 60)

    private let zones: any ZoneSyncing
    private let sleep: @Sendable (Duration) async throws -> Void
    private let now: @Sendable () -> Date

    private var session: Session?
    private var run: Task<Void, Never>?
    private var rerun = false
    private var foreground = false
    private var wakes: [String: any WakeStopping] = [:]
    private var tick: Task<Void, Never>?
    private var retryTask: Task<Void, Never>?
    private var refusalContinuations: [UUID: AsyncStream<[ZoneRefusal]>.Continuation] = [:]
    private var changeContinuations: [UUID: AsyncStream<Void>.Continuation] = [:]

    /// The refusals of the last round, for the screens.
    public private(set) var refusals: [ZoneRefusal] = []
    /// The zones whose mailbox is full in the last round.
    public private(set) var quotaFull: [FfiZone] = []
    /// The last report (tests, diagnostics).
    public private(set) var lastReport: FfiZoneRoundReport?
    /// Tests: rounds run, and the most that ran at once.
    private(set) var roundsRun = 0
    private var running = 0
    private(set) var maxConcurrentRounds = 0

    public init(
        zones: any ZoneSyncing,
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.zones = zones
        self.sleep = sleep
        self.now = now
    }

    public var client: any ZoneSyncing { zones }

    public func sessionUnlocked(_ session: Session) {
        self.session = session
    }

    public func sessionLocked() {
        session = nil
    }

    /// A private round ended: a zone round now (or one more after the one in progress).
    public func afterPrivateRound() async {
        kick()
        await run?.value
    }

    /// Runs a zone round now and returns when it is done.
    public func syncNow() async {
        kick()
        await run?.value
    }

    public func enterForeground() async {
        foreground = true
        startTick()
        await refreshWakes()
    }

    public func enterBackground() {
        foreground = false
        tick?.cancel()
        tick = nil
        for w in wakes.values { w.stop() }
        wakes = [:]
    }

    /// The refusals after each round.
    public func refusalUpdates() -> AsyncStream<[ZoneRefusal]> {
        let (stream, continuation) = AsyncStream<[ZoneRefusal]>.makeStream()
        let id = UUID()
        refusalContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeRefusalContinuation(id) }
        }
        continuation.yield(refusals)
        return stream
    }

    /// One element per zone round that changed the store.
    public func remoteChanges() -> AsyncStream<Void> {
        let (stream, continuation) = AsyncStream<Void>.makeStream()
        let id = UUID()
        changeContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeChangeContinuation(id) }
        }
        return stream
    }

    // MARK: - Rounds

    private func kick() {
        if run != nil {
            rerun = true
            return
        }
        run = Task { await self.runRounds() }
    }

    private func runRounds() async {
        repeat {
            rerun = false
            await round()
        } while rerun
        run = nil
        if foreground { await refreshWakes() }
    }

    private func round() async {
        running += 1
        maxConcurrentRounds = max(maxConcurrentRounds, running)
        roundsRun += 1
        let report = await zones.runRound(session: session, now: Int64(now().timeIntervalSince1970))
        running -= 1
        lastReport = report
        quotaFull = report.quotaFull
        refusals = report.refusals.map { ZoneRefusal(zone: $0.zone, removed: $0.removed) }
        for c in refusalContinuations.values { c.yield(refusals) }
        if report.changed {
            for c in changeContinuations.values { c.yield(()) }
        }
        if report.rerun { rerun = true }
        if let after = report.retryAfterSeconds { scheduleRetry(.seconds(Int(after))) }
    }

    private func scheduleRetry(_ delay: Duration) {
        retryTask?.cancel()
        let sleep = self.sleep
        retryTask = Task { [weak self] in
            do { try await sleep(delay) } catch { return }
            guard !Task.isCancelled else { return }
            await self?.retryFired()
        }
    }

    private func retryFired() {
        retryTask = nil
        kick()
    }

    // MARK: - Foreground

    private func startTick() {
        guard tick == nil else { return }
        let sleep = self.sleep
        tick = Task { [weak self] in
            while !Task.isCancelled {
                do { try await sleep(Self.foregroundInterval) } catch { return }
                guard !Task.isCancelled else { return }
                await self?.tickFired()
            }
        }
    }

    private func tickFired() {
        guard foreground else { return }
        kick()
    }

    private func wakeFired() {
        guard foreground else { return }
        kick()
    }

    /// One listener per zone topic the last round synced; listeners of zones gone are stopped.
    private func refreshWakes() async {
        let topics = await zones.wakeTopics()
        let wanted = Set(topics.map(\.mailboxId))
        for (id, w) in wakes where !wanted.contains(id) {
            w.stop()
            wakes[id] = nil
        }
        for topic in topics where wakes[topic.mailboxId] == nil {
            guard foreground else { return }
            do {
                let handle = try await zones.startWake(topic.wake) { [weak self] in
                    Task { await self?.wakeFired() }
                }
                if foreground, wakes[topic.mailboxId] == nil {
                    wakes[topic.mailboxId] = handle
                } else {
                    handle.stop()
                }
            } catch {
                // No wake channel: the zone still syncs after each private round and every 15 min.
            }
        }
    }

    /// Tests: zone listeners running.
    var wakeCount: Int { wakes.count }

    private func removeRefusalContinuation(_ id: UUID) {
        refusalContinuations[id] = nil
    }

    private func removeChangeContinuation(_ id: UUID) {
        changeContinuations[id] = nil
    }
}
