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

/// One page of server changes since the last fetch of this client.
public struct RemoteBatch: Sendable, Equatable {
    public var changes: [RemoteRecord]
    public var moreComing: Bool

    public init(changes: [RemoteRecord], moreComing: Bool) {
        self.changes = changes
        self.moreComing = moreComing
    }
}

/// Errors of a remote. `offline` (or a `URLError`) makes the coordinator retry later.
public enum RemoteStoreError: Error, Equatable, Sendable {
    case offline
    case accountUnavailable
    /// French message for the UI, never a record content.
    case other(String)
}

/// The server side of sync (CloudKit in the apps, `InMemoryRemote` in tests and previews).
///
/// - `fetchChanges` returns the changes since the previous call of this client (the remote keeps its
///   change token), one page at a time; the caller calls again while `moreComing`.
/// - `send` stores a batch atomically: every save is conditional on its `serverMeta` (nil = the record
///   must not exist), deletions are unconditional. One refused save fails the whole batch: the refused
///   records come back as `conflict(server:)`, the others as `failed`.
public protocol RemoteRecordStore: Sendable {
    func fetchChanges() async throws -> RemoteBatch
    func send(_ changes: [RemoteRecord]) async throws -> [SendResult]
    func accountAvailable() async -> Bool
}
