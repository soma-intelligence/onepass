import Foundation

/// A fake server for tests and previews, shared by several coordinators to simulate several devices.
///
/// Models what the coordinator relies on from CloudKit: a tag per record (`serverMeta`, a `UInt64` in
/// 8 little-endian bytes) that changes on every write, atomic batches with conditional saves and
/// unconditional deletions, a change log read through tokens (the position in the log, 8 bytes; each
/// device keeps its own in its store, the server keeps no cursor), paged fetches and batch limits
/// (a larger batch is refused). It can also attack: `tamper`, `withhold`, `replay` and `forgeDeletion`,
/// and change the signed-in account (`setAccountIdentity`, `changeIdentityAfterNextFetch`).
public actor InMemoryRemote: RemoteRecordStore {
    private struct Stored {
        var version: UInt64
        var data: Data?
        /// nil once deleted.
        var tag: UInt64?
        /// Position in the change log.
        var sequence: UInt64
        /// Every version this record was saved with (for `replay`).
        var history: [UInt64: Data] = [:]
    }

    public let pageSize: Int
    /// CloudKit realism: a fetch from scratch (no token, or an expired one) returns live records only,
    /// not the deletions of the past.
    public let omitsTombstonesOnFullFetch: Bool
    public nonisolated let maxBatchRecords: Int
    public nonisolated let maxBatchBytes: Int
    private var records: [RecordName: Stored] = [:]
    private var withheld: Set<RecordName> = []
    private var sequence: UInt64 = 0
    private var lastTag: UInt64 = 0
    private var offline = false
    private var available = true
    private var identity: String? = "utilisateur-icloud-a"
    private var nextFailure: RemoteStoreError?
    private var resetPending = false
    private var tokenExpired = false
    private var brokenToken = false
    private var changeCount: UInt64 = 0
    /// Fetch pages still served before the next fetch throws `offline` (once).
    private var fetchPagesBeforeFailure: Int?
    /// Saved batches still accepted before the next send throws `offline` (once).
    private var sendsBeforeFailure: Int?
    /// Every send throws `offline` (fetches still work).
    private var sendsOffline = false
    /// Runs once after the next saved batch, before `send` returns (another device acting between two
    /// batches of one round).
    private var afterSave: (@Sendable () async -> Void)?
    /// Identity switched in once the next fetch has served its last page (and whether the switch is
    /// announced through `accountChangeCount`, like `CKAccountChanged`).
    private var identityAfterFetch: (identity: String?, announce: Bool)?
    /// Calls to `accountIdentity()` (each one is a network call on CloudKit).
    public private(set) var identityRequests = 0
    /// Every batch received, in order (names only).
    public private(set) var sentBatches: [[RecordName]] = []

    public init(
        pageSize: Int = 400, maxBatchRecords: Int = 400, maxBatchBytes: Int = 1_572_864,
        omitsTombstonesOnFullFetch: Bool = false
    ) {
        self.omitsTombstonesOnFullFetch = omitsTombstonesOnFullFetch
        self.pageSize = max(1, pageSize)
        self.maxBatchRecords = max(1, maxBatchRecords)
        self.maxBatchBytes = max(1, maxBatchBytes)
    }

    /// The tag in its `serverMeta` form (also the token form of a log position).
    public static func serverMeta(tag: UInt64) -> Data {
        withUnsafeBytes(of: tag.littleEndian) { Data($0) }
    }

    static func decode(_ bytes: Data?) -> UInt64? {
        guard let bytes, bytes.count == 8 else { return nil }
        return bytes.reversed().reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    }

    // MARK: - RemoteRecordStore

    public func fetchChanges(since token: Data?) async throws -> RemoteBatch {
        try checkFailure()
        if let pages = fetchPagesBeforeFailure {
            fetchPagesBeforeFailure = pages > 0 ? pages - 1 : nil
            if pages == 0 { throw RemoteStoreError.offline }
        }
        var cursor = Self.decode(token) ?? 0
        var restarted = false
        if tokenExpired, token != nil {
            tokenExpired = false
            cursor = 0
            restarted = true
        }
        let fullFetch = cursor == 0
        let changed = records
            .filter { $0.value.sequence > cursor && !withheld.contains($0.key) }
            .filter { !(fullFetch && omitsTombstonesOnFullFetch && $0.value.data == nil) }
            .sorted { $0.value.sequence < $1.value.sequence }
        let page = changed.prefix(pageSize)
        let next = page.last?.value.sequence ?? cursor
        if brokenToken {
            brokenToken = false
            return RemoteBatch(changes: page.map { remoteRecord($0.key, $0.value) }, moreComing: true, token: nil)
        }
        let moreComing = changed.count > page.count
        if !moreComing, let pending = identityAfterFetch {
            identityAfterFetch = nil
            identity = pending.identity
            if pending.announce { changeCount += 1 }
        }
        return RemoteBatch(
            changes: page.map { remoteRecord($0.key, $0.value) },
            moreComing: moreComing,
            token: Self.serverMeta(tag: next), restartedFromScratch: restarted)
    }

    public func send(_ changes: [RemoteRecord]) async throws -> [SendResult] {
        try checkFailure()
        if sendsOffline { throw RemoteStoreError.offline }
        if let sends = sendsBeforeFailure {
            sendsBeforeFailure = sends > 0 ? sends - 1 : nil
            if sends == 0 { throw RemoteStoreError.offline }
        }
        let results = try save(changes)
        if results.contains(where: { if case .saved = $0 { true } else { false } }), let hook = afterSave {
            afterSave = nil
            await hook()
        }
        return results
    }

    private func save(_ changes: [RemoteRecord]) throws -> [SendResult] {
        guard changes.count <= maxBatchRecords, changes.reduce(0, { $0 + $1.batchBytes }) <= maxBatchBytes else {
            throw RemoteStoreError.other(String(localized: "Lot trop volumineux pour le serveur.", bundle: VaultKitStrings.bundle))
        }
        sentBatches.append(changes.map(\.name))
        let refused = Set(changes.filter { change in
            change.data != nil && Self.decode(change.serverMeta) != records[change.name]?.tag
        }.map(\.name))
        guard refused.isEmpty else {
            return changes.map { change in
                guard refused.contains(change.name) else { return .failed(name: change.name) }
                if let stored = records[change.name] {
                    return .conflict(server: remoteRecord(change.name, stored))
                }
                return .conflict(server: RemoteRecord(name: change.name, version: 0, data: nil, serverMeta: nil))
            }
        }
        return changes.map { change in
            sequence += 1
            if let data = change.data {
                lastTag += 1
                var stored = records[change.name]
                    ?? Stored(version: change.version, data: data, tag: lastTag, sequence: sequence)
                stored.version = change.version
                stored.data = data
                stored.tag = lastTag
                stored.sequence = sequence
                stored.history[change.version] = data
                records[change.name] = stored
                return .saved(name: change.name, serverMeta: Self.serverMeta(tag: lastTag))
            }
            if var stored = records[change.name] {
                stored.data = nil
                stored.tag = nil
                stored.sequence = sequence
                records[change.name] = stored
            }
            return .saved(name: change.name, serverMeta: nil)
        }
    }

    public func accountAvailable() async -> Bool { available }

    public func accountIdentity() async throws -> String? {
        try checkOffline()
        identityRequests += 1
        return identity
    }

    public func accountChangeCount() async -> UInt64 { changeCount }

    private func checkOffline() throws {
        if offline { throw RemoteStoreError.offline }
    }

    private func checkFailure() throws {
        if offline { throw RemoteStoreError.offline }
        if resetPending {
            resetPending = false
            throw RemoteStoreError.zoneReset
        }
        if let failure = nextFailure {
            nextFailure = nil
            throw failure
        }
    }

    private func remoteRecord(_ name: RecordName, _ stored: Stored) -> RemoteRecord {
        RemoteRecord(
            name: name, version: stored.version, data: stored.data,
            serverMeta: stored.tag.map(Self.serverMeta(tag:)))
    }

    /// Rewrites a stored record with a new tag, so every device fetches it again.
    private func rewrite(_ name: RecordName, _ change: (inout Stored) -> Void) {
        guard var stored = records[name] else { return }
        change(&stored)
        sequence += 1
        lastTag += 1
        stored.sequence = sequence
        stored.tag = lastTag
        records[name] = stored
    }

    // MARK: - Test controls

    /// Flips the last byte of the record's data (an attacker editing the blob).
    public func tamper(name: RecordName) {
        guard records[name]?.data?.isEmpty == false else { return }
        rewrite(name) { stored in
            guard var data = stored.data else { return }
            data[data.index(before: data.endIndex)] ^= 0xFF
            stored.data = data
        }
    }

    /// Logs a deletion of the record that no client asked for (a forged tombstone).
    public func forgeDeletion(name: RecordName) {
        guard records[name] != nil else { return }
        sequence += 1
        records[name]?.data = nil
        records[name]?.tag = nil
        records[name]?.sequence = sequence
    }

    /// Stops serving the record in fetches (it stays on the server for sends).
    public func withhold(name: RecordName) {
        withheld.insert(name)
    }

    /// Serves an older (or the same) saved version of the record again, with a new tag.
    public func replay(name: RecordName, version: UInt64) {
        guard let old = records[name]?.history[version] else { return }
        rewrite(name) { stored in
            stored.version = version
            stored.data = old
        }
    }

    /// While offline, fetches and sends throw `RemoteStoreError.offline`.
    public func setOffline(_ offline: Bool) {
        self.offline = offline
    }

    /// The next fetch or send throws `error`, once.
    public func failNext(with error: RemoteStoreError) {
        nextFailure = error
    }

    /// The next fetch given a token ignores it and serves the zone from the start (a CloudKit
    /// `changeTokenExpired`), flagged `restartedFromScratch`.
    public func expireTokens() {
        tokenExpired = true
    }

    /// Simulates a lost zone: every record is wiped (log positions and tags keep growing) and the next
    /// fetch or send throws `RemoteStoreError.zoneReset`, once.
    public func simulateReset() {
        records.removeAll()
        withheld.removeAll()
        resetPending = true
    }

    public func setAccountAvailable(_ available: Bool) {
        self.available = available
    }

    /// Simulates another Apple ID signing in (or nil: an account the remote cannot name).
    public func setAccountIdentity(_ identity: String?) {
        self.identity = identity
    }

    /// Simulates another Apple ID signing in between the fetch and the send of a round: the identity
    /// changes once the next fetch has served its last page. `announce`: the change is also signalled
    /// through `accountChangeCount()` (CloudKit posts `CKAccountChanged`).
    public func changeIdentityAfterNextFetch(to identity: String?, announce: Bool) {
        identityAfterFetch = (identity, announce)
    }

    /// The fetch that follows `pages` served pages throws `offline`, once (a fetch cut between two pages).
    public func failFetch(afterPages pages: Int) {
        fetchPagesBeforeFailure = max(0, pages)
    }

    /// The send that follows `batches` sends throws `offline`, once (a round cut between two batches).
    public func failSend(afterBatches batches: Int) {
        sendsBeforeFailure = max(0, batches)
    }

    /// While set, every send throws `offline` and fetches still work (a device that can read but not
    /// write, or a round held back while another device writes).
    public func setSendsOffline(_ offline: Bool) {
        sendsOffline = offline
    }

    /// Runs `hook` once, after the next batch that saves something and before that send returns.
    public func afterNextSave(_ hook: @escaping @Sendable () async -> Void) {
        afterSave = hook
    }

    /// Serves one page that announces more pages without a token (a broken remote), once.
    public func breakNextPageToken() {
        brokenToken = true
    }

    /// Live record (nil when absent or deleted).
    public func record(_ name: RecordName) -> RemoteRecord? {
        guard let stored = records[name], stored.data != nil else { return nil }
        return remoteRecord(name, stored)
    }

    /// Tag of every live record.
    public func tags() -> [RecordName: UInt64] {
        records.compactMapValues(\.tag)
    }
}
