import Foundation

/// A record as the server holds it. `data == nil` is a deletion. `serverMeta` is opaque to the core
/// (CloudKit: the encoded system fields of the `CKRecord`; `InMemoryRemote`: an 8 byte tag).
public struct RemoteRecord: Sendable, Equatable {
    public var name: RecordName
    public var version: UInt64
    public var data: Data?
    public var serverMeta: Data?

    public init(name: RecordName, version: UInt64, data: Data?, serverMeta: Data?) {
        self.name = name
        self.version = version
        self.data = data
        self.serverMeta = serverMeta
    }
}

/// Outcome of one record of a sent batch.
public enum SendResult: Sendable, Equatable {
    /// Stored (or deleted, `serverMeta == nil`) by the server.
    case saved(name: RecordName, serverMeta: Data?)
    /// The server holds another version (`data == nil`: it deleted the record).
    case conflict(server: RemoteRecord)
    /// Not stored because another record of the atomic batch was refused.
    case failed(name: RecordName)

    public var name: RecordName {
        switch self {
        case .saved(let name, _), .failed(let name): name
        case .conflict(let server): server.name
        }
    }
}

extension RemoteRecord {
    /// What this record weighs in a batch: data, server metadata and name.
    public var batchBytes: Int {
        (data?.count ?? 0) + (serverMeta?.count ?? 0) + name.string.utf8.count
    }
}

/// One page of server changes after `token`. `token` is where the next fetch starts (nil: unchanged).
public struct RemoteBatch: Sendable, Equatable {
    public var changes: [RemoteRecord]
    public var moreComing: Bool
    public var token: Data?
    /// The remote ignored the given token (expired) and served the zone from the start. Like a fetch
    /// without token, such a fetch carries live records only, never the deletions of the past.
    public var restartedFromScratch: Bool

    public init(changes: [RemoteRecord], moreComing: Bool, token: Data?, restartedFromScratch: Bool = false) {
        self.changes = changes
        self.moreComing = moreComing
        self.token = token
        self.restartedFromScratch = restartedFromScratch
    }
}

/// Errors of a remote. `offline` (or a `URLError`) and `retryable` make the coordinator retry later.
public enum RemoteStoreError: Error, Equatable, Sendable {
    case offline
    case accountUnavailable
    /// Busy or rate limited server: retry, after the given delay when the server gave one.
    case retryable(after: Duration?)
    /// The server lost everything it held (its zone was deleted and recreated). The caller forgets its
    /// change token, queues every stored record again and runs a new round.
    case zoneReset
    /// A record of the zone could not be read (never skipped: the fetch would advance past it).
    /// Retried like `retryable`; the coordinator reports it apart after several rounds in a row.
    case recordUnreadable
    /// The signed-in iCloud account is not the one this store synced with (spec 7, ruling of the final
    /// review): thrown by the coordinator itself, never by a remote.
    case accountChanged
    /// French message for the UI, never a record content.
    case other(String)
}

/// The server side of sync (CloudKit in the apps, `InMemoryRemote` in tests and previews).
///
/// - `fetchChanges(since:)` returns one page of the changes after `token` (nil: from the start) and the
///   token of that page; the caller calls again while `moreComing`. The caller owns the token: it
///   persists it once the page is staged in the local store. A remote never keeps or persists a cursor
///   of its own, so a page lost before it was staged is served again.
/// - `send` stores a batch atomically: every save is conditional on its `serverMeta` (nil = the record
///   must not exist), deletions are unconditional. One refused save fails the whole batch: the refused
///   records come back as `conflict(server:)`, the others as `failed`. A saved record with data always
///   comes back with a non-nil `serverMeta`.
/// - A batch never holds more than `maxBatchRecords` records or `maxBatchBytes` bytes
///   (`RemoteRecord.batchBytes`); the caller splits larger sends.
/// - `accountIdentity()` names the signed-in account (CloudKit: the user record name), stable for that
///   account and different for any other; nil when the remote cannot tell. The coordinator binds its
///   store to the first identity it sees and stops on any other one.
/// - `accountChangeCount()` grows each time the remote learns that the signed-in account may have
///   changed (CloudKit: `CKAccountChanged`), without any network call. Default: always 0.
/// - `accountRecordIDs()` lists the account ids (32 hex characters) of the account params records the
///   zone holds, without touching any local store. Default: every page read from the start.
public protocol RemoteRecordStore: Sendable {
    var maxBatchRecords: Int { get }
    var maxBatchBytes: Int { get }
    func fetchChanges(since token: Data?) async throws -> RemoteBatch
    func send(_ changes: [RemoteRecord]) async throws -> [SendResult]
    func accountAvailable() async -> Bool
    func accountIdentity() async throws -> String?
    func accountChangeCount() async -> UInt64
    func accountRecordIDs() async throws -> Set<String>
}

extension RemoteRecordStore {
    public func accountChangeCount() async -> UInt64 { 0 }

    public func accountRecordIDs() async throws -> Set<String> {
        var ids: Set<String> = []
        var token: Data?
        while true {
            let batch = try await fetchChanges(since: token)
            for change in batch.changes where change.name.kind == 1 && change.data != nil {
                ids.insert(change.name.id)
            }
            guard batch.moreComing else { return ids }
            // More pages without a token would read the same page forever.
            guard let next = batch.token else { throw RemoteStoreError.retryable(after: nil) }
            token = next
        }
    }
}
