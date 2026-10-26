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

    public init(changes: [RemoteRecord], moreComing: Bool, token: Data?) {
        self.changes = changes
        self.moreComing = moreComing
        self.token = token
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
public protocol RemoteRecordStore: Sendable {
    var maxBatchRecords: Int { get }
    var maxBatchBytes: Int { get }
    func fetchChanges(since token: Data?) async throws -> RemoteBatch
    func send(_ changes: [RemoteRecord]) async throws -> [SendResult]
    func accountAvailable() async -> Bool
}
