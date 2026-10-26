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
        try await ensureSetup()
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
            } catch let error as CKError where error.code == .zoneNotFound && !retriedZone {
                retriedZone = true
                zoneReady = false
                try await ensureSetup()
            } catch {
                throw CloudKitMapping.storeError(for: error)
            }
        }
    }

    private func fetchPage(since cursor: CKServerChangeToken?) async throws -> RemoteBatch {
        let result = try await database.recordZoneChanges(
            inZoneWith: zoneID, since: cursor, resultsLimit: maxBatchRecords)
        var changes: [RemoteRecord] = []
        for (_, modification) in result.modificationResultsByID {
            // An invalid record (foreign name, missing field) is skipped: it cannot be a vault record.
            guard case .success(let modified) = modification,
                let remote = try? CloudKitMapping.remote(from: modified.record)
            else { continue }
            changes.append(remote)
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
        try await ensureSetup()
        var retriedZone = false
        while true {
            do {
                return try await sendOnce(changes)
            } catch let error as CKError where error.code == .zoneNotFound && !retriedZone {
                retriedZone = true
                zoneReady = false
                try await ensureSetup()
            } catch {
                throw CloudKitMapping.storeError(for: error)
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
        var results: [SendResult] = []
        for change in changes {
            let id = CKRecord.ID(recordName: change.name.string, zoneID: zoneID)
            if change.data == nil {
                switch outcome.deleteResults[id] {
                case .success?: results.append(.saved(name: change.name, serverMeta: nil))
                case .failure(let error)?: results.append(try perRecord(change, error))
                case nil: results.append(.failed(name: change.name))
                }
            } else {
                switch outcome.saveResults[id] {
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
        return try changes.map { change in
            let id = CKRecord.ID(recordName: change.name.string, zoneID: zoneID)
            guard let itemError = byID[id] else { return .failed(name: change.name) }
            return try perRecord(change, itemError)
        }
    }

    private func perRecord(_ change: RemoteRecord, _ error: Error) throws -> SendResult {
        switch CloudKitMapping.sendResult(name: change.name, isDeletion: change.data == nil, error: error) {
        case .success(let result): return result
        case .failure(let failure): throw failure
        }
    }

    // MARK: - Setup

    /// Creates the zone and the database subscription once per process (both are idempotent).
    private func ensureSetup() async throws {
        do {
            if !zoneReady {
                _ = try await database.modifyRecordZones(saving: [CKRecordZone(zoneID: zoneID)], deleting: [])
                zoneReady = true
            }
            if !subscriptionReady {
                let subscription = CKDatabaseSubscription(subscriptionID: CloudKitMapping.subscriptionID)
                let info = CKSubscription.NotificationInfo()
                info.shouldSendContentAvailable = true
                subscription.notificationInfo = info
                _ = try await database.modifySubscriptions(saving: [subscription], deleting: [])
                subscriptionReady = true
            }
        } catch {
            throw CloudKitMapping.storeError(for: error)
        }
    }
}
#endif
