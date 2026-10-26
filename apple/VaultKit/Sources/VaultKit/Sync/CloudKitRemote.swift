#if ONEPASS_CLOUDKIT
import CloudKit
import Foundation

/// CloudKit private database as a `RemoteRecordStore` (spec 4 point 7, rulings R7 and R8): zone
/// `OnePass`, record type `OPRecord`, atomic conditional batches, zone change tokens owned by the caller.
public actor CloudKitRemote: RemoteRecordStore {
    public nonisolated let maxBatchRecords = 400
    public nonisolated let maxBatchBytes = 1_572_864

    private let container: CKContainer
    private let database: CKDatabase
    private let zoneID: CKRecordZone.ID
    private var zoneReady = false
    private var subscriptionReady = false

    public init(containerIdentifier: String = "iCloud.me.somalabs.onepass") {
        container = CKContainer(identifier: containerIdentifier)
        database = container.privateCloudDatabase
        zoneID = CKRecordZone.ID(zoneName: CloudKitMapping.zoneName, ownerName: CKCurrentUserDefaultName)
    }

    public func accountAvailable() async -> Bool {
        (try? await container.accountStatus()) == .available
    }

    // MARK: - Fetch

    public func fetchChanges(since token: Data?) async throws -> RemoteBatch {
        try await ensureZone()
        await ensureSubscription()
        var cursor = CloudKitMapping.decodeToken(token)
        var retriedZone = false
        var restarted = false
        while true {
            do {
                return try await fetchPage(since: cursor)
            } catch let error as CKError where error.code == .changeTokenExpired && !restarted {
                // The cursor is too old: serve the zone again from the start.
                restarted = true
                cursor = nil
            } catch {
                guard let loss = CloudKitMapping.zoneLoss(in: error) else {
                    throw CloudKitMapping.storeError(for: error)
                }
                try await recreateZone()
                if CloudKitMapping.resetsStore(loss, hadState: token != nil) { throw RemoteStoreError.zoneReset }
                if retriedZone { throw CloudKitMapping.storeError(for: error) }
                retriedZone = true
            }
        }
    }

    private func fetchPage(since cursor: CKServerChangeToken?) async throws -> RemoteBatch {
        let result = try await database.recordZoneChanges(
            inZoneWith: zoneID, since: cursor, resultsLimit: maxBatchRecords)
        var changes: [RemoteRecord] = []
        for (_, modification) in result.modificationResultsByID {
            switch modification {
            case .success(let modified):
                // An invalid record (foreign name, missing field) is skipped: it cannot be a vault record.
                if let remote = try? CloudKitMapping.remote(from: modified.record) { changes.append(remote) }
            case .failure:
                // Never advance past a record that could not be read.
                throw RemoteStoreError.retryable(after: nil)
            }
        }
        for deletion in result.deletions {
            if let remote = try? CloudKitMapping.deletion(recordID: deletion.recordID) {
                changes.append(remote)
            }
        }
        return CloudKitMapping.batch(
            changes: changes, moreComing: result.moreComing,
            token: CloudKitMapping.encode(token: result.changeToken))
    }

    // MARK: - Send

    public func send(_ changes: [RemoteRecord]) async throws -> [SendResult] {
        guard !changes.isEmpty else { return [] }
        try await ensureZone()
        await ensureSubscription()
        var retriedZone = false
        while true {
            do {
                return try await sendOnce(changes)
            } catch {
                guard let loss = CloudKitMapping.zoneLoss(in: error) else {
                    throw CloudKitMapping.storeError(for: error)
                }
                try await recreateZone()
                let hadState = changes.contains { $0.serverMeta != nil }
                if CloudKitMapping.resetsStore(loss, hadState: hadState) { throw RemoteStoreError.zoneReset }
                if retriedZone { throw CloudKitMapping.storeError(for: error) }
                retriedZone = true
            }
        }
    }

    private func sendOnce(_ changes: [RemoteRecord]) async throws -> [SendResult] {
        var saving: [CKRecord] = []
        var deleting: [CKRecord.ID] = []
        for change in changes {
            if change.data == nil {
                deleting.append(CKRecord.ID(recordName: change.name.string, zoneID: zoneID))
            } else {
                saving.append(try CloudKitMapping.record(from: change, zoneID: zoneID))
            }
        }
        let outcome: (
            saveResults: [CKRecord.ID: Result<CKRecord, Error>],
            deleteResults: [CKRecord.ID: Result<Void, Error>]
        )
        do {
            outcome = try await database.modifyRecords(
                saving: saving, deleting: deleting, savePolicy: .ifServerRecordUnchanged, atomically: true)
        } catch let error as CKError where error.code == .partialFailure {
            return try partialResults(error, changes: changes)
        }
        // Keyed by record name (the zone is ours).
        let saved = Dictionary(
            outcome.saveResults.filter { $0.key.zoneID.zoneName == zoneID.zoneName }.map { ($0.key.recordName, $0.value) },
            uniquingKeysWith: { first, _ in first })
        let deleted = Dictionary(
            outcome.deleteResults.filter { $0.key.zoneID.zoneName == zoneID.zoneName }.map { ($0.key.recordName, $0.value) },
            uniquingKeysWith: { first, _ in first })
        var results: [SendResult] = []
        for change in changes {
            let key = change.name.string
            if change.data == nil {
                switch deleted[key] {
                case .success?: results.append(.saved(name: change.name, serverMeta: nil))
                case .failure(let error)?: results.append(try perRecord(change, error))
                case nil: results.append(.failed(name: change.name))
                }
            } else {
                switch saved[key] {
                case .success(let record)?:
                    results.append(.saved(name: change.name, serverMeta: CloudKitMapping.systemFields(of: record)))
                case .failure(let error)?: results.append(try perRecord(change, error))
                case nil: results.append(.failed(name: change.name))
                }
            }
        }
        return results
    }

    private func partialResults(_ error: CKError, changes: [RemoteRecord]) throws -> [SendResult] {
        let byID = error.partialErrorsByItemID ?? [:]
        guard !byID.isEmpty else { throw error }
        var byName: [String: Error] = [:]
        for (key, value) in byID {
            if let id = key as? CKRecord.ID, id.zoneID.zoneName == zoneID.zoneName { byName[id.recordName] = value }
        }
        return try changes.map { change in
            guard let itemError = byName[change.name.string] else { return .failed(name: change.name) }
            return try perRecord(change, itemError)
        }
    }

    private func perRecord(_ change: RemoteRecord, _ error: Error) throws -> SendResult {
        // A lost zone aborts the call: `send` recreates it (and tells the caller when data was lost).
        if CloudKitMapping.requiresZoneRecreation(error) { throw error }
        switch CloudKitMapping.sendResult(name: change.name, isDeletion: change.data == nil, error: error) {
        case .success(let result): return result
        case .failure(let failure): throw failure
        }
    }

    // MARK: - Setup

    private func ensureZone() async throws {
        guard !zoneReady else { return }
        do {
            _ = try await database.modifyRecordZones(saving: [CKRecordZone(zoneID: zoneID)], deleting: [])
            zoneReady = true
        } catch {
            throw CloudKitMapping.storeError(for: error)
        }
    }

    private func recreateZone() async throws {
        zoneReady = false
        try await ensureZone()
    }

    /// Creates the database subscription once per process (idempotent). A failure never blocks a fetch or
    /// a send: the flag stays false and the next call tries again.
    private func ensureSubscription() async {
        guard !subscriptionReady else { return }
        let subscription = CKDatabaseSubscription(subscriptionID: CloudKitMapping.subscriptionID)
        let info = CKSubscription.NotificationInfo()
        info.shouldSendContentAvailable = true
        subscription.notificationInfo = info
        do {
            _ = try await database.modifySubscriptions(saving: [subscription], deleting: [])
            subscriptionReady = true
        } catch {
            subscriptionReady = false
        }
    }
}
#endif
