import Foundation
import os

/// Schedules the sync rounds of an account on a mailbox (cross-platform spec 4.10, 4.14). The round
/// itself is the core's (`MailboxSync.run_round`: fetch, rebase, send, home check); this actor only
/// decides when one runs and what the status says.
///
/// One round at a time: triggers that come during a round give one more round after it. A round
/// that asks for another (`rerun`) gets it at once; a server delay (`retry_after_seconds`) is used as
/// is, otherwise failures back off along `retryDelays`. The session handed over by `sessionUnlocked`
/// goes to each round (rebase, health, home check); a locked device rounds without it.
///
/// While the app is in the foreground the mailbox's wake channel kicks a round on each change made
/// elsewhere (`enterForeground`, `enterBackground`). Once the account's signed home names another
/// place (`HomeMoved`), no round runs again: the app follows the new home with a new coordinator.
public actor MailboxSyncCoordinator: SyncTrigger {
    private let sync: any MailboxSyncing
    private let serverName: String
    private let debounce: Duration
    private let retryDelays: [Duration]
    private let sleep: @Sendable (Duration) async throws -> Void
    private let now: @Sendable () -> Date

    public private(set) var status: SyncStatus = .idle(lastSync: nil)
    private var session: Session?
    private var statusContinuations: [UUID: AsyncStream<SyncStatus>.Continuation] = [:]
    private var changeContinuations: [UUID: AsyncStream<Void>.Continuation] = [:]

    private var run: Task<Void, Never>?
    private var rerun = false
    private var debounceTask: Task<Void, Never>?
    private var retryTask: Task<Void, Never>?
    private var retryAttempt = 0
    private var moved = false
    private var foreground = false
    private var wake: (any WakeStopping)?
    /// Tests: rounds run, and the most that ran at once.
    private(set) var roundsRun = 0
    private var running = 0
    private(set) var maxConcurrentRounds = 0

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "mailbox-sync")

    /// `serverName`: what the status names (the host, or "Serveur OnePass"). `sleep` and `now` are
    /// injected by tests.
    public init(
        sync: any MailboxSyncing, serverName: String, debounce: Duration = .seconds(2),
        retryDelays: [Duration] = SyncCoordinator.retryDelays,
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.sync = sync
        self.serverName = serverName
        self.debounce = debounce
        self.retryDelays = retryDelays.isEmpty ? SyncCoordinator.retryDelays : retryDelays
        self.sleep = sleep
        self.now = now
    }

    // MARK: - Public API

    public nonisolated var syncsWithServer: Bool { true }

    /// The server this account syncs with, for the settings line.
    public nonisolated var server: String { serverName }
    /// The mailbox client this coordinator rounds with (push token registration).
    public nonisolated var client: any MailboxSyncing { sync }

    /// Whether the account's home moved: no round runs any more.
    public var homeMoved: Bool { moved }

    /// Runs a round now (or joins the one in progress, plus one more) and returns when it is done.
    public func syncNow() async {
        kick()
        await run?.value
    }

    /// The current status, then every change.
    public func statusUpdates() -> AsyncStream<SyncStatus> {
        let (stream, continuation) = AsyncStream<SyncStatus>.makeStream()
        let id = UUID()
        statusContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeStatusContinuation(id) }
        }
        continuation.yield(status)
        return stream
    }

    /// One element per round that changed the store (fetched changes or a rebase).
    public func remoteChanges() -> AsyncStream<Void> {
        let (stream, continuation) = AsyncStream<Void>.makeStream()
        let id = UUID()
        changeContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeChangeContinuation(id) }
        }
        return stream
    }

    /// The app came to the foreground: listen to the wake channel and run a round.
    public func enterForeground() async {
        foreground = true
        kick()
        await startWake()
    }

    /// The app left the foreground: stop listening (APNs wakes it from now on).
    public func enterBackground() {
        foreground = false
        stopWake()
    }

    // MARK: - SyncTrigger

    /// Debounced: one round `debounce` after the last write.
    public func localChangesWritten() async {
        debounceTask?.cancel()
        let (sleep, delay) = (self.sleep, debounce)
        debounceTask = Task { [weak self] in
            do { try await sleep(delay) } catch { return }
            guard !Task.isCancelled else { return }
            await self?.debounceFired()
        }
    }

    public func sessionUnlocked(_ session: Session) async {
        self.session = session
        kick()
    }

    public func sessionLocked() async {
        session = nil
    }

    // MARK: - Rounds

    private func kick() {
        guard !moved else { return }
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
        } while rerun && !moved
        run = nil
    }

    private func debounceFired() {
        debounceTask = nil
        kick()
    }

    private func retryFired() {
        retryTask = nil
        kick()
    }

    private func wakeFired() {
        guard foreground else { return }
        kick()
    }

    private func round() async {
        guard !moved else { return }
        running += 1
        maxConcurrentRounds = max(maxConcurrentRounds, running)
        roundsRun += 1
        setStatus(.syncing)
        let stamp = Int64(now().timeIntervalSince1970)
        let report = await sync.runRound(session: session, now: stamp)
        running -= 1
        if report.changed || !report.rebased.isEmpty { emitRemoteChange() }
        apply(report)
    }

    private func apply(_ report: FfiRoundReport) {
        switch report.status {
        case .idle:
            retryAttempt = 0
            retryTask?.cancel()
            retryTask = nil
            setStatus(.idle(lastSync: now()))
        case .offline:
            setStatus(.offline)
            scheduleRetry(report)
        case .retrying:
            setStatus(.error(Self.retryingMessage))
            scheduleRetry(report)
        case .clockSkew:
            setStatus(.error(Self.clockSkewMessage))
            scheduleRetry(report)
        case .waitingForServer:
            setStatus(.waitingForMailbox)
            scheduleRetry(report)
        case .refused(let kind):
            Self.log.error("remote data refused: \(kind, privacy: .public)")
            setStatus(.refused(kind: kind))
        case .unsettled:
            setStatus(.syncing)
            scheduleRetry(report)
        case .unreadable:
            setStatus(.error(Self.unreadableMessage))
            scheduleRetry(report)
        case .homeMoved(let baseUrl):
            Self.log.notice("the account's home moved, mailbox rounds stopped")
            moved = true
            rerun = false
            retryTask?.cancel()
            retryTask = nil
            debounceTask?.cancel()
            stopWake()
            setStatus(.homeMoved(server: baseUrl.flatMap { URL(string: $0)?.host() } ?? "iCloud"))
            return
        }
        if report.rerun { rerun = true }
    }

    static var retryingMessage: String {
        String(localized: "sync.mailbox.retrying", bundle: VaultKitStrings.bundle)
    }

    static var clockSkewMessage: String {
        String(localized: "sync.mailbox.clockSkew", bundle: VaultKitStrings.bundle)
    }

    static var unreadableMessage: String {
        String(localized: "sync.mailbox.unreadable", bundle: VaultKitStrings.bundle)
    }

    /// The server's delay when it gave one, otherwise the next step of the backoff.
    private func scheduleRetry(_ report: FfiRoundReport) {
        retryTask?.cancel()
        let delay: Duration
        if let after = report.retryAfterSeconds {
            delay = .seconds(Int(after))
        } else {
            delay = retryDelays[min(retryAttempt, retryDelays.count - 1)]
            retryAttempt += 1
        }
        let sleep = self.sleep
        retryTask = Task { [weak self] in
            do { try await sleep(delay) } catch { return }
            guard !Task.isCancelled else { return }
            await self?.retryFired()
        }
    }

    // MARK: - Wake

    private func startWake() async {
        guard wake == nil, !moved else { return }
        do {
            let handle = try await sync.startWake { [weak self] in
                Task { await self?.wakeFired() }
            }
            if foreground, !moved, wake == nil {
                wake = handle
            } else {
                handle.stop()
            }
        } catch {
            // No wake channel: rounds still run on opening and on writes.
            Self.log.notice("mailbox wake channel unavailable")
        }
    }

    private func stopWake() {
        wake?.stop()
        wake = nil
    }

    // MARK: - Streams

    private func setStatus(_ new: SyncStatus) {
        status = new
        for continuation in statusContinuations.values { continuation.yield(new) }
    }

    private func emitRemoteChange() {
        for continuation in changeContinuations.values { continuation.yield(()) }
    }

    private func removeStatusContinuation(_ id: UUID) {
        statusContinuations[id] = nil
    }

    private func removeChangeContinuation(_ id: UUID) {
        changeContinuations[id] = nil
    }
}
