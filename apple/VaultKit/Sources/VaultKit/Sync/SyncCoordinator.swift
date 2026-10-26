import Foundation
import os

/// Runs sync rounds between the local store and a remote (spec 3.5 and 4 point 7).
///
/// A round: fetch every page (`stage_remote` each change, then one `commit_remote`), `rebase_all` when
/// a session is unlocked, then send every pending change as one atomic batch (`mark_pushed` on `saved`).
/// A conflict stages the server records and starts a new turn (fetch, rebase, send), three turns at
/// most: the staged records are committed with the fetch of that turn, in the same `commit_remote`, so a
/// conflicting manifest never lands in `base` before the items it lists. A network error sets `.offline` and retries after 30 s, 2 min, then every
/// 10 min; an integrity error from the rebase sets `.refused(kind)`.
///
/// One round at a time: every store call (fetch, commit, rebase, send) runs inside the round, so a
/// rebase never overlaps a commit. Triggers that come during a round coalesce into one more round.
/// Locked device: fetch and commit still run, held vaults send nothing (the core leaves them out of
/// `pending_changes`) until `sessionUnlocked` hands over a session for the rebase.
public actor SyncCoordinator: SyncTrigger {
    public static let retryDelays: [Duration] = [.seconds(30), .seconds(120), .seconds(600)]
    static let maxTurns = 3

    private let store: SyncStoreHandle
    private let remote: (any RemoteRecordStore)?
    private let debounce: Duration
    private let retryDelays: [Duration]
    private let sleep: @Sendable (Duration) async throws -> Void
    private let now: @Sendable () -> Date

    public private(set) var status: SyncStatus
    private var session: Session?
    private var statusContinuations: [UUID: AsyncStream<SyncStatus>.Continuation] = [:]
    private var changeContinuations: [UUID: AsyncStream<Void>.Continuation] = [:]

    /// The rounds in progress (one after the other); `rerun` asks for one more.
    private var run: Task<Void, Never>?
    private var rerun = false
    /// Store access is exclusive: rounds and `remoteHasAccount` take turns.
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var debounceTask: Task<Void, Never>?
    private var retryTask: Task<Void, Never>?
    private var retryAttempt = 0
    /// Conflicting server records staged by a send, committed by the next fetch.
    private var stagedConflicts = false

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "sync")

    /// `remote == nil`: sync disabled. `sleep` and `now` are injected by tests.
    public init(
        store: SyncStoreHandle, remote: (any RemoteRecordStore)?, debounce: Duration = .seconds(2),
        retryDelays: [Duration] = SyncCoordinator.retryDelays,
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.store = store
        self.remote = remote
        self.debounce = debounce
        self.retryDelays = retryDelays.isEmpty ? SyncCoordinator.retryDelays : retryDelays
        self.sleep = sleep
        self.now = now
        status = remote == nil ? .disabled : .idle(lastSync: nil)
    }

    // MARK: - Public API

    /// Runs a round now (or joins the one in progress, plus one more) and returns when it is done.
    public func syncNow() async {
        guard remote != nil else { return }
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

    /// One element per applied remote change set (records that differ from what the store knew) and
    /// per rebase: the app reloads its `VaultSession` on each.
    public func remoteChanges() -> AsyncStream<Void> {
        let (stream, continuation) = AsyncStream<Void>.makeStream()
        let id = UUID()
        changeContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeChangeContinuation(id) }
        }
        return stream
    }

    /// Fetches into the store, then tells whether an account exists (account creation refuses a second
    /// account in the same iCloud, spec 7). No remote: false. Network errors are thrown.
    public func remoteHasAccount() async throws -> Bool {
        guard let remote else { return false }
        await acquire()
        defer { release() }
        try await fetchAll(remote)
        let store = store
        return try await CoreThread.run { try store.hasAccount() }
    }

    // MARK: - SyncTrigger

    /// Debounced: one round `debounce` after the last write.
    public func localChangesWritten() async {
        guard remote != nil else { return }
        debounceTask?.cancel()
        let (sleep, delay) = (self.sleep, debounce)
        debounceTask = Task { [weak self] in
            do { try await sleep(delay) } catch { return }
            guard !Task.isCancelled else { return }
            await self?.debounceFired()
        }
    }

    /// Keeps the session for rebases and starts a round (held vaults can be rebased now).
    public func sessionUnlocked(_ session: Session) async {
        self.session = session
        guard remote != nil else { return }
        kick()
    }

    public func sessionLocked() async {
        session = nil
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
            await acquire()
            await round()
            release()
        } while rerun
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

    private enum RoundError: Error {
        case unsettled
    }

    private func round() async {
        guard let remote else { return }
        guard await remote.accountAvailable() else {
            setStatus(.error("Aucun compte iCloud n'est disponible."))
            return
        }
        setStatus(.syncing)
        do {
            var turn = 0
            while true {
                turn += 1
                try await fetchAll(remote)
                try await rebaseIfUnlocked()
                if try await sendPending(remote) { break }
                if turn >= Self.maxTurns { throw RoundError.unsettled }
            }
            retryAttempt = 0
            retryTask?.cancel()
            retryTask = nil
            setStatus(.idle(lastSync: now()))
        } catch RemoteStoreError.offline {
            setStatus(.offline)
            scheduleRetry()
        } catch is URLError {
            setStatus(.offline)
            scheduleRetry()
        } catch RoundError.unsettled {
            Self.log.notice("sync round ended with conflicts left")
            setStatus(.error("La synchronisation n'a pas abouti, nouvel essai bientôt."))
            scheduleRetry()
        } catch OnePassError.Integrity(let kind) {
            Self.log.error("remote data refused: \(kind, privacy: .public)")
            setStatus(.refused(kind: kind))
        } catch let error as RemoteStoreError {
            switch error {
            case .accountUnavailable: setStatus(.error("Aucun compte iCloud n'est disponible."))
            case .other(let message): setStatus(.error(message))
            case .offline: setStatus(.offline)
            }
        } catch {
            setStatus(.error(VaultError(error).localizedMessage))
        }
    }

    /// Every page, staged, then committed at once (a manifest never shows without its items).
    /// Records whose `serverMeta` matches what the store already holds are skipped (our own pushes
    /// coming back): the remaining ones are the applied change set.
    private func fetchAll(_ remote: any RemoteRecordStore) async throws {
        let store = store
        var staged = 0
        while true {
            let batch = try await remote.fetchChanges()
            if !batch.changes.isEmpty {
                let changes = batch.changes
                staged += try await CoreThread.run {
                    var count = 0
                    for change in changes {
                        let known = try store.serverMeta(kind: change.name.kind, id: change.name.id)
                        if change.serverMeta != nil, known == change.serverMeta { continue }
                        if change.serverMeta == nil, change.data == nil, known == nil { continue }
                        try store.stageRemote(record: FfiRemoteRecord(change))
                        count += 1
                    }
                    return count
                }
            }
            if !batch.moreComing { break }
        }
        guard staged > 0 || stagedConflicts else { return }
        _ = try await CoreThread.run { try store.commitRemote() }
        stagedConflicts = false
        emitRemoteChange()
    }

    /// Unlocked only. A session locked meanwhile is dropped (`Locked`), the round goes on without it.
    private func rebaseIfUnlocked() async throws {
        guard let session else { return }
        do {
            let rebased = try await CoreThread.run { try session.rebaseAll() }
            if !rebased.isEmpty { emitRemoteChange() }
        } catch OnePassError.Locked {
            if self.session === session { self.session = nil }
        }
    }

    /// Sends every pending change as one atomic batch. Returns true when nothing is left to retry.
    private func sendPending(_ remote: any RemoteRecordStore) async throws -> Bool {
        let store = store
        let outgoing: [(change: FfiRecordChange, record: RemoteRecord)] = try await CoreThread.run {
            try store.pendingChanges().map { change in
                let name = RecordName(kind: change.kind, id: change.id)
                let meta = try store.serverMeta(kind: change.kind, id: change.id)
                return (change, RemoteRecord(name: name, version: change.version, data: change.data, serverMeta: meta))
            }
        }
        guard !outgoing.isEmpty else { return true }
        let results = try await remote.send(outgoing.map(\.record))

        let byName = Dictionary(outgoing.map { ($0.record.name, $0.change) }, uniquingKeysWith: { first, _ in first })
        var pushed: [(FfiRecordChange, Data?)] = []
        var conflicts: [RemoteRecord] = []
        var settled = true
        for result in results {
            switch result {
            case .saved(let name, let meta):
                if let change = byName[name] { pushed.append((change, meta)) }
            case .conflict(let server):
                conflicts.append(server)
                settled = false
            case .failed:
                settled = false
            }
        }
        if results.count < outgoing.count { settled = false }
        let toPush = pushed
        let toStage = conflicts
        try await CoreThread.run {
            for (change, meta) in toPush {
                try store.markPushed(kind: change.kind, id: change.id, version: change.version, serverMeta: meta)
            }
            for server in toStage { try store.stageRemote(record: FfiRemoteRecord(server)) }
        }
        if !toStage.isEmpty { stagedConflicts = true }
        return settled
    }

    private func scheduleRetry() {
        retryTask?.cancel()
        let delay = retryDelays[min(retryAttempt, retryDelays.count - 1)]
        retryAttempt += 1
        let sleep = self.sleep
        retryTask = Task { [weak self] in
            do { try await sleep(delay) } catch { return }
            guard !Task.isCancelled else { return }
            await self?.retryFired()
        }
    }

    // MARK: - Exclusive store access

    private func acquire() async {
        if !busy {
            busy = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    /// Hands the store to the next waiter (still busy) or frees it.
    private func release() {
        if waiters.isEmpty {
            busy = false
        } else {
            waiters.removeFirst().resume()
        }
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

extension FfiRemoteRecord {
    init(_ record: RemoteRecord) {
        self.init(
            kind: record.name.kind, id: record.name.id, version: record.version, data: record.data,
            serverMeta: record.serverMeta)
    }
}
