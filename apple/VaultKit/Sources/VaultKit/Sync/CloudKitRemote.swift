// Always compiled: Xcode does not pass the app's ONEPASS_CLOUDKIT condition to package targets.
// Nothing here runs until the app creates a `CloudKitRemote`, which it does only under
// `#if ONEPASS_CLOUDKIT` (signed Release-CloudKit configuration, ruling R8).
#if canImport(CloudKit)
import CloudKit
import Foundation
import os

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
    private let accountChanges = AccountChangeCounter()

    public init(containerIdentifier: String = "iCloud.me.somalabs.onepass") {
        container = CKContainer(identifier: containerIdentifier)
        database = container.privateCloudDatabase
        zoneID = CKRecordZone.ID(zoneName: CloudKitMapping.zoneName, ownerName: CKCurrentUserDefaultName)
    }

    public func accountAvailable() async -> Bool {
        (try? await container.accountStatus()) == .available
    }

    /// Bumped on every `CKAccountChanged` (posted by CloudKit when the signed-in Apple ID changes or
    /// signs out): the coordinator then checks the identity again before its next send. No network.
    public func accountChangeCount() async -> UInt64 {
        accountChanges.value
    }

    /// The record name of the signed-in user: stable for one Apple ID in this container, different
    /// for any other.
    public func accountIdentity() async throws -> String? {
        do {
            return try await container.userRecordID().recordName
        } catch {
            throw CloudKitMapping.storeError(for: error)
        }
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
                var batch = try await fetchPage(since: cursor)
                batch.restartedFromScratch = restarted
                return batch
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

    /// The account ids of the zone's account params records, read from the start without creating
    /// the zone or its subscription: a missing zone holds no account.
    public func accountRecordIDs() async throws -> Set<String> {
        var ids: Set<String> = []
        var cursor: CKServerChangeToken?
        while true {
            let batch: RemoteBatch
            do {
                batch = try await fetchPage(since: cursor)
            } catch {
                if CloudKitMapping.zoneLoss(in: error) != nil { return [] }
                throw error is RemoteStoreError ? error : CloudKitMapping.storeError(for: error)
            }
            for change in batch.changes where change.name.kind == 1 && change.data != nil {
                ids.insert(change.name.id)
            }
            guard batch.moreComing else { return ids }
            guard let next = CloudKitMapping.decodeToken(batch.token) else {
                throw RemoteStoreError.retryable(after: nil)
            }
            cursor = next
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
                throw RemoteStoreError.recordUnreadable
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
/// Counts `CKAccountChanged` notifications from creation on. The observer only bumps a locked counter
/// (no actor hop, no `Task`), and is removed with the counter.
final class AccountChangeCounter: @unchecked Sendable {
    private let count = OSAllocatedUnfairLock(initialState: UInt64(0))
    private var observer: (any NSObjectProtocol)?

    init() {
        let count = count
        observer = NotificationCenter.default.addObserver(
            forName: .CKAccountChanged, object: nil, queue: nil
        ) { _ in
            count.withLock { $0 &+= 1 }
        }
    }

    var value: UInt64 { count.withLock { $0 } }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }
}
#endif
