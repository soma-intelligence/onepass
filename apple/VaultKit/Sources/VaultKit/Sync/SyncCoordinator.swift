import Foundation
import os

/// Runs sync rounds between the local store and a remote (spec 3.5 and 4 point 7).
///
/// A round: fetch every page from the stored change token (each page validated, staged, then its token
/// persisted), one `commit_remote` after the last page, `rebase_all` when a session is unlocked, then
/// send every pending change as one atomic batch (split only past the remote's limits, items always
/// before their manifest) and `mark_pushed` each saved record. A conflict stages the server records and
/// starts a new turn (fetch and commit, rebase, send), three turns at most. A network or busy error
/// retries after 30 s, 2 min, then every 10 min (or after the delay the server asked for); an integrity
/// error from the rebase sets `.refused(kind)`, kept until a rebase succeeds.
///
/// iCloud account binding: the first round stores the remote's `accountIdentity()` in the store meta.
/// A later round (or `remoteHasAccount`) that meets another identity touches nothing (no fetch, no
/// send) and reports `.accountChanged` until `acceptAccountChange()`: the change token and server tags
/// of one Apple ID must never meet the zone of another.
///
/// One round at a time: every store call (fetch, commit, rebase, send) runs inside the round, so a
/// rebase never overlaps a commit. Triggers that come during a round coalesce into one more round.
/// Locked device: fetch and commit still run, held vaults send nothing (the core leaves them out of
/// `pending_changes`) until `sessionUnlocked` hands over a session for the rebase.
public actor SyncCoordinator: SyncTrigger {
    public static let retryDelays: [Duration] = [.seconds(30), .seconds(120), .seconds(600)]
    static let maxTurns = 3
    /// Store meta key of the remote change token (the handle namespaces it under `sync.`).
    static let tokenKey = "remote.token"
    /// Store meta key of the iCloud account identity the store is bound to.
    static let accountKey = "remote.account"
    /// Rounds in a row that met an unreadable record before the status says so plainly.
    static let unreadableRoundsBeforeReport = 5

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
    /// Kind of the last integrity refusal of a rebase, until a rebase succeeds.
    private var refusal: String?
    /// Rounds in a row that ended on `RemoteStoreError.recordUnreadable`.
    private var unreadableRounds = 0
    /// Tests: runs on the core thread after a page is staged, before its token is saved.
    var afterPageStaged: (@Sendable () throws -> Void)?

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

    /// "Réessayer" after "Données refusées": forgets the change token (an empty token is a cleared one),
    /// so the next round fetches everything from scratch through `beginFullFetch` and settles rows the
    /// server no longer holds, then sends as usual. Returns when that round is done. No remote: no-op.
    public func refetchFromScratch() async {
        guard remote != nil else { return }
        await acquire()
        let store = store
        do {
            try await CoreThread.run { try store.setMeta(key: Self.tokenKey, value: Data()) }
        } catch {
            Self.log.error("change token not cleared")
        }
        release()
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

    /// One element per applied remote change set (records that differ from what the store knew, or a
    /// commit that changed manifests) and per rebase: the app reloads its `VaultSession` on each.
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
    /// account in the same iCloud, spec 7). No remote: false. Network errors are thrown. A lost zone is
    /// handled by the fetch (one reset); a second one in the same call is thrown as `zoneReset`.
    public func remoteHasAccount() async throws -> Bool {
        guard let remote else { return false }
        await acquire()
        defer { release() }
        do {
            try await fetchAll(remote)
        } catch RemoteStoreError.accountChanged {
            setStatus(.accountChanged)
            throw RemoteStoreError.accountChanged
        }
        let store = store
        return try await CoreThread.run { try store.hasAccount() }
    }

    /// The user confirmed that this store now syncs with the signed-in iCloud account (after
    /// `.accountChanged`). The new identity is stored, the old change token and server tags are
    /// forgotten as after a lost zone (every local record is queued again for the new account's zone
    /// after the next complete fetch), then a round runs. Not offered in the M2 interface (status text
    /// and explanation only). No remote: no-op.
    public func acceptAccountChange() async {
        guard let remote else { return }
        await acquire()
        let store = store
        do {
            if let identity = try await remote.accountIdentity() {
                try await CoreThread.run {
                    try store.setMeta(key: Self.accountKey, value: Data(identity.utf8))
                    try store.beginZoneReset(tokenKey: Self.tokenKey)
                }
            }
        } catch {
            Self.log.error("iCloud account change not accepted")
        }
        release()
        kick()
        await run?.value
    }

    /// Tests: simulates a crash between staging a page and saving its token.
    func setAfterPageStaged(_ hook: (@Sendable () throws -> Void)?) {
        afterPageStaged = hook
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
            var resets = 0
            while true {
                do {
                    turn += 1
                    try await fetchAll(remote)
                    try await rebaseIfUnlocked()
                    if try await sendPending(remote) { break }
                    if turn >= Self.maxTurns { throw RoundError.unsettled }
                } catch RemoteStoreError.zoneReset {
                    // The server lost its data: forget its tags and our token, then fetch from scratch;
                    // the records it does not hold are queued after that fetch (`fetchAll`).
                    // Counted here: resets thrown by the send step (or by a second one inside a fetch).
                    // The third gives up as unsettled, so at most two are handled; each restarts the
                    // turn count, so a round runs at most 3 turns + 2 x 3 turns = 9 turns. A fetch also
                    // handles one reset of its own per call, without counting here (it needs no turn).
                    resets += 1
                    if resets > 2 { throw RoundError.unsettled }
                    try await resetForLostZone()
                    turn = 0
                }
            }
            retryAttempt = 0
            unreadableRounds = 0
            retryTask?.cancel()
            retryTask = nil
            // A locked round cannot clear a refusal: the refused vault is still held.
            setStatus(refusal.map { .refused(kind: $0) } ?? .idle(lastSync: now()))
        } catch RemoteStoreError.offline {
            setStatus(.offline)
            scheduleRetry(after: nil)
        } catch is URLError {
            setStatus(.offline)
            scheduleRetry(after: nil)
        } catch RemoteStoreError.retryable(let after) {
            setStatus(.error("Le serveur est momentanément indisponible, nouvel essai bientôt."))
            scheduleRetry(after: after)
        } catch RemoteStoreError.recordUnreadable {
            unreadableRounds += 1
            if unreadableRounds >= Self.unreadableRoundsBeforeReport {
                Self.log.error("a remote record stays unreadable")
                setStatus(.error(Self.unreadableMessage))
            } else {
                setStatus(.error("Le serveur est momentanément indisponible, nouvel essai bientôt."))
            }
            scheduleRetry(after: nil)
        } catch RemoteStoreError.accountChanged {
            Self.log.notice("iCloud account changed, sync stopped")
            setStatus(.accountChanged)
        } catch RoundError.unsettled {
            Self.log.notice("sync round ended with conflicts left")
            setStatus(.error("La synchronisation n'a pas abouti, nouvel essai bientôt."))
            scheduleRetry(after: nil)
        } catch OnePassError.Integrity(let kind) {
            Self.log.error("remote data refused: \(kind, privacy: .public)")
            refusal = kind
            setStatus(.refused(kind: kind))
        } catch let error as RemoteStoreError {
            switch error {
            case .accountUnavailable: setStatus(.error("Aucun compte iCloud n'est disponible."))
            case .other(let message): setStatus(.error(message))
            case .offline, .retryable, .zoneReset, .recordUnreadable: setStatus(.offline)
            case .accountChanged: setStatus(.accountChanged)
            }
        } catch {
            setStatus(.error(VaultError(error).localizedMessage))
        }
    }

    /// Every page from the stored token: each page is validated, staged, then its token saved (a page
    /// lost before staging is fetched again). After the last page, always one `commit_remote`, which
    /// also applies anything left in `staging` (an interrupted fetch, conflicting records of a send),
    /// so staged rows never outlive a complete fetch. Records whose `serverMeta` matches the stored one
    /// (our own pushes coming back) are not staged; deletions are always staged.
    private func fetchAll(_ remote: any RemoteRecordStore) async throws {
        try await checkAccountIdentity(remote)
        let store = store
        let hook = afterPageStaged
        var token = try await CoreThread.run { try store.meta(key: Self.tokenKey) }
        // An empty token is a cleared one (a lost zone): fetch from the start.
        if token?.isEmpty == true { token = nil }
        // A fetch from scratch carries no deletions of the past: the store forgets its server tags first
        // and settles the rows the server did not return after the commit (`finish_full_fetch`).
        if token == nil { try await CoreThread.run { try store.beginFullFetch() } }
        var changed = 0
        var resets = 0
        while true {
            let batch: RemoteBatch
            do {
                batch = try await remote.fetchChanges(since: token)
            } catch RemoteStoreError.zoneReset where resets == 0 {
                resets += 1
                try await resetForLostZone()
                token = nil
                continue
            }
            if batch.restartedFromScratch { try await CoreThread.run { try store.beginFullFetch() } }
            let valid = batch.changes.filter(Self.isValid)
            if valid.count < batch.changes.count {
                Self.log.notice("skipped \(batch.changes.count - valid.count, privacy: .public) unknown remote records")
            }
            let next = batch.token
            changed += try await CoreThread.run {
                var count = 0
                for change in valid {
                    let known = try store.serverMeta(kind: change.name.kind, id: change.name.id)
                    if change.data != nil {
                        if let meta = change.serverMeta, let known, CloudKitMapping.sameServerVersion(meta, known) {
                            continue
                        }
                        count += 1
                    } else if known != nil {
                        count += 1
                    }
                    try store.stageRemote(record: FfiRemoteRecord(change))
                }
                try hook?()
                if let next { try store.setMeta(key: Self.tokenKey, value: next) }
                return count
            }
            if let next { token = next }
            if !batch.moreComing { break }
            // More pages without a new token would fetch the same page forever: retry later.
            if next == nil {
                Self.log.error("remote announced more changes without a token")
                throw RemoteStoreError.retryable(after: nil)
            }
        }
        let (vaults, dropped) = try await CoreThread.run {
            let vaults = try store.commitRemote()
            // After a fetch from scratch: rows the server did not return are deleted, or queued again
            // after a zone reset (no-op otherwise).
            return (vaults, try store.finishFullFetch())
        }
        if changed > 0 || !vaults.isEmpty || dropped { emitRemoteChange() }
    }

    /// Binds the store to the remote's account at the first sync; throws `accountChanged` on any other
    /// account. A remote that cannot name its account (nil) is not checked.
    private func checkAccountIdentity(_ remote: any RemoteRecordStore) async throws {
        guard let identity = try await remote.accountIdentity() else { return }
        let current = Data(identity.utf8)
        let store = store
        let stored = try await CoreThread.run { try store.meta(key: Self.accountKey) }
        if let stored, !stored.isEmpty {
            if stored != current { throw RemoteStoreError.accountChanged }
            return
        }
        try await CoreThread.run { try store.setMeta(key: Self.accountKey, value: current) }
    }

    nonisolated static let unreadableMessage =
        "Un enregistrement iCloud reste illisible : la synchronisation est bloquée. OnePass réessaiera."

    /// The remote lost everything. Step 1, atomic in the core: server tags, staged pages and the change
    /// token are dropped and a persisted flag is set. Nothing is queued yet, so a stale local record
    /// never overwrites a newer version another device uploads to the new zone; step 2 runs after the
    /// next complete fetch (`fetchAll`), also after a restart.
    private func resetForLostZone() async throws {
        let store = store
        try await CoreThread.run { try store.beginZoneReset(tokenKey: Self.tokenKey) }
    }

    /// A record the core can stage: known kind (1 to 6), canonical id, version that fits SQLite.
    static func isValid(_ record: RemoteRecord) -> Bool {
        (1...6).contains(record.name.kind)
            && RecordName(string: record.name.string) == record.name
            && record.version <= UInt64(Int64.max)
    }

    /// Unlocked only. A session locked meanwhile is dropped (`Locked`), the round goes on without it.
    private func rebaseIfUnlocked() async throws {
        guard let session else { return }
        do {
            let rebased = try await CoreThread.run { try session.rebaseAll() }
            refusal = nil
            if !rebased.isEmpty { emitRemoteChange() }
        } catch OnePassError.Locked {
            if self.session === session { self.session = nil }
        }
    }

    private struct Outgoing: Sendable {
        var change: FfiRecordChange
        var record: RemoteRecord
    }

    /// Sends every pending change, as one atomic batch unless the remote's limits force a split.
    /// Returns true when nothing is left to retry; stops at the first batch that is not fully saved.
    private func sendPending(_ remote: any RemoteRecordStore) async throws -> Bool {
        let store = store
        let outgoing: [Outgoing] = try await CoreThread.run {
            try store.pendingChanges().map { change in
                let name = RecordName(kind: change.kind, id: change.id)
                let meta = try store.serverMeta(kind: change.kind, id: change.id)
                return Outgoing(
                    change: change,
                    record: RemoteRecord(name: name, version: change.version, data: change.data, serverMeta: meta))
            }
        }
        guard !outgoing.isEmpty else { return true }
        let batches = Self.split(
            Self.ordered(outgoing), maxRecords: remote.maxBatchRecords, maxBytes: remote.maxBatchBytes)
        for batch in batches {
            if try await !send(batch, to: remote) { return false }
        }
        return true
    }

    /// One batch: `mark_pushed` for each saved record, conflicting server records staged (committed
    /// by the next fetch). A data save without `serverMeta` counts as failed.
    private func send(_ batch: [Outgoing], to remote: any RemoteRecordStore) async throws -> Bool {
        let results = try await remote.send(batch.map(\.record))
        let byName = Dictionary(batch.map { ($0.record.name, $0.change) }, uniquingKeysWith: { first, _ in first })
        var pushed: [(FfiRecordChange, Data?)] = []
        var conflicts: [RemoteRecord] = []
        var settled = results.count >= batch.count
        for result in results {
            switch result {
            case .saved(let name, let meta):
                guard let change = byName[name] else { continue }
                if change.data != nil, meta == nil {
                    settled = false
                } else {
                    pushed.append((change, meta))
                }
            case .conflict(let server):
                if Self.isValid(server) { conflicts.append(server) }
                settled = false
            case .failed:
                settled = false
            }
        }
        let store = store
        let (toPush, toStage) = (pushed, conflicts)
        try await CoreThread.run {
            for (change, meta) in toPush {
                try store.markPushed(kind: change.kind, id: change.id, version: change.version, serverMeta: meta)
            }
            for server in toStage { try store.stageRemote(record: FfiRemoteRecord(server)) }
        }
        return settled
    }

    /// Pending order regrouped per vault: records outside vaults (account, keysets, vault keys and
    /// metas), then for each vault with a pending manifest its items followed by its manifest, then
    /// items without a pending manifest, then deletions in core order (after every manifest).
    private static func ordered(_ outgoing: [Outgoing]) -> [Outgoing] {
        let writes = outgoing.filter { $0.change.data != nil }
        let deletions = outgoing.filter { $0.change.data == nil }
        var result = writes.filter { $0.change.kind < 5 }
        var items: [String: [Outgoing]] = [:]
        var itemOrder: [String] = []
        for item in writes where item.change.kind == 5 {
            let vault = item.change.data.map { $0.prefix(16).map { String(format: "%02x", $0) }.joined() } ?? ""
            if items[vault] == nil { itemOrder.append(vault) }
            items[vault, default: []].append(item)
        }
        for manifest in writes where manifest.change.kind == 6 {
            result += items.removeValue(forKey: manifest.change.id) ?? []
            result.append(manifest)
        }
        for vault in itemOrder { result += items[vault] ?? [] }
        result += writes.filter { $0.change.kind > 6 }
        return result + deletions
    }

    /// Consecutive slices within the limits (a single oversized record goes alone).
    private static func split(_ outgoing: [Outgoing], maxRecords: Int, maxBytes: Int) -> [[Outgoing]] {
        var batches: [[Outgoing]] = []
        var current: [Outgoing] = []
        var bytes = 0
        for item in outgoing {
            let size = item.record.batchBytes
            if !current.isEmpty, current.count >= max(1, maxRecords) || bytes + size > maxBytes {
                batches.append(current)
                current = []
                bytes = 0
            }
            current.append(item)
            bytes += size
        }
        if !current.isEmpty { batches.append(current) }
        return batches
    }

    /// `after`: the server's delay, used as is. Otherwise the next step of the backoff.
    private func scheduleRetry(after: Duration?) {
        retryTask?.cancel()
        let delay: Duration
        if let after {
            delay = after
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
