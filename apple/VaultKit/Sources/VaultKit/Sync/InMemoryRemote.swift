import Foundation

/// A fake server for tests and previews, shared by several coordinators to simulate several devices
/// (`client(_:)` gives each one its own change cursor).
///
/// Models what the coordinator relies on from CloudKit: a tag per record (`serverMeta`, a `UInt64` in
/// 8 little-endian bytes) that changes on every write, atomic batches with conditional saves and
/// unconditional deletions, a change cursor per client and paged fetches. It can also attack:
/// `tamper`, `withhold` and `replay`.
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
    private var records: [RecordName: Stored] = [:]
    private var withheld: Set<RecordName> = []
    private var cursors: [String: UInt64] = [:]
    private var sequence: UInt64 = 0
    private var lastTag: UInt64 = 0
    private var offline = false
    private var available = true

    public init(pageSize: Int = 400) {
        self.pageSize = max(1, pageSize)
    }

    /// One device's view of this server.
    public nonisolated func client(_ id: String) -> InMemoryRemoteClient {
        InMemoryRemoteClient(server: self, clientID: id)
    }

    /// The tag in its `serverMeta` form.
    public static func serverMeta(tag: UInt64) -> Data {
        withUnsafeBytes(of: tag.littleEndian) { Data($0) }
    }

    static func tag(of serverMeta: Data?) -> UInt64? {
        guard let serverMeta, serverMeta.count == 8 else { return nil }
        return serverMeta.reduce(into: (value: UInt64(0), shift: UInt64(0))) { acc, byte in
            acc.value |= UInt64(byte) << acc.shift
            acc.shift += 8
        }.value
    }

    // MARK: - RemoteRecordStore (as the "default" client)

    public func fetchChanges() async throws -> RemoteBatch { try fetch(client: "default") }
    public func send(_ changes: [RemoteRecord]) async throws -> [SendResult] { try save(changes) }
    public func accountAvailable() async -> Bool { available }

    // MARK: - Server

    func fetch(client: String) throws -> RemoteBatch {
        if offline { throw RemoteStoreError.offline }
        let cursor = cursors[client] ?? 0
        let changed = records
            .filter { $0.value.sequence > cursor && !withheld.contains($0.key) }
            .sorted { $0.value.sequence < $1.value.sequence }
        let page = changed.prefix(pageSize)
        if let last = page.last { cursors[client] = last.value.sequence }
        return RemoteBatch(
            changes: page.map { remoteRecord($0.key, $0.value) },
            moreComing: changed.count > page.count)
    }

    func save(_ changes: [RemoteRecord]) throws -> [SendResult] {
        if offline { throw RemoteStoreError.offline }
        let refused = Set(changes.filter { change in
            change.data != nil && Self.tag(of: change.serverMeta) != records[change.name]?.tag
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

    private func remoteRecord(_ name: RecordName, _ stored: Stored) -> RemoteRecord {
        RemoteRecord(
            name: name, version: stored.version, data: stored.data,
            serverMeta: stored.tag.map(Self.serverMeta(tag:)))
    }

    /// Rewrites a stored record with a new tag, so every client fetches it again.
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

    /// Stops serving the record in fetches (it stays on the server for sends).
    public func withhold(name: RecordName) {
        withheld.insert(name)
    }

    /// Serves an older saved version of the record again.
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

    public func setAccountAvailable(_ available: Bool) {
        self.available = available
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

/// One client of an `InMemoryRemote`, with its own change cursor.
public struct InMemoryRemoteClient: RemoteRecordStore {
    public let server: InMemoryRemote
    public let clientID: String

    public func fetchChanges() async throws -> RemoteBatch {
        try await server.fetch(client: clientID)
    }

    public func send(_ changes: [RemoteRecord]) async throws -> [SendResult] {
        try await server.save(changes)
    }

    public func accountAvailable() async -> Bool {
        await server.accountAvailable()
    }
}
