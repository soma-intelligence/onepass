// Always compiled, never exercised by the tests (they use `InMemoryRemoteChannel`).
#if canImport(CloudKit)
import CloudKit
import Foundation
import os

/// `RemoteChannel` over the CloudKit private database (agent-ready spec 5.2): zone `AgentRequests`,
/// record type `RemoteMessage`, fields `to` (device id in clear, for the subscription), `blob` and
/// `expires_at`. A reader polls every `pollInterval` (2 s) while its stream is open, that is while a
/// request waits; `subscribe(device:)` adds the push that wakes the device.
public actor CloudKitRemoteChannel: RemoteChannel {
    public static let zoneName = "AgentRequests"
    public static let recordType = "RemoteMessage"
    enum Field {
        static let to = "to"
        static let blob = "blob"
        static let expiresAt = "expires_at"
    }

    private let database: CKDatabase
    private let zoneID: CKRecordZone.ID
    private let pollInterval: Duration
    private var zoneReady = false
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "remote")

    public init(containerIdentifier: String = "iCloud.me.somalabs.onepass", pollInterval: Duration = .seconds(2)) {
        database = CKContainer(identifier: containerIdentifier).privateCloudDatabase
        zoneID = CKRecordZone.ID(zoneName: Self.zoneName, ownerName: CKCurrentUserDefaultName)
        self.pollInterval = pollInterval
    }

    public func post(_ m: RemoteMessage) async throws {
        do {
            try await ensureZone()
            let record = CKRecord(recordType: Self.recordType, recordID: recordID(m.id))
            record[Field.to] = m.to as NSString
            record[Field.blob] = m.blob as NSData
            record[Field.expiresAt] = m.expiresAt as NSDate
            _ = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .allKeys)
        } catch {
            Self.log.error("remote message not posted")
            throw RemoteChannelError.unreachable
        }
    }

    public nonisolated func messages(for device: String) -> AsyncStream<RemoteMessage> {
        AsyncStream { continuation in
            let task = Task { await self.poll(device: device, into: continuation) }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public func delete(_ id: String) async {
        _ = try? await database.modifyRecords(saving: [], deleting: [recordID(id)])
    }

    public func purgeExpired(now: Date) async {
        let predicate = NSPredicate(format: "%K < %@", Field.expiresAt, now as NSDate)
        let expired: [RemoteMessage]
        do {
            expired = try await query(predicate)
        } catch {
            Self.log.error("expired remote messages not listed")
            return
        }
        guard !expired.isEmpty else { return }
        _ = try? await database.modifyRecords(saving: [], deleting: expired.map { recordID($0.id) })
    }

    /// Localization key of the iPhone alert, resolved in the app's strings: generic text only
    /// ("Demande d'un agent" / "Request from an agent"), since Apple sees it. No item, vault, command,
    /// secret or Mac name ever goes in the push.
    public static let alertKey = "REMOTE_REQUEST_ALERT"

    /// The visible push that tells `device` a record for it was created (spec 5.2). The alert is
    /// generic and mutable: on the iPhone a Notification Service Extension (Task 9) sets
    /// `interruptionLevel = .timeSensitive` and fills the Mac name locally ("Demande d'un agent sur
    /// <nom du Mac>"), since a CloudKit alert cannot carry either. No silent push: the alert alone
    /// wakes the extension.
    public func subscribe(device: String) async throws {
        do {
            try await ensureZone()
            let subscription = CKQuerySubscription(
                recordType: Self.recordType, predicate: NSPredicate(format: "%K == %@", Field.to, device),
                subscriptionID: "remote-\(device)", options: [.firesOnRecordCreation])
            let info = CKSubscription.NotificationInfo()
            info.titleLocalizationKey = Self.alertKey
            info.alertLocalizationKey = Self.alertKey
            info.soundName = "default"
            info.shouldSendMutableContent = true
            subscription.notificationInfo = info
            _ = try await database.modifySubscriptions(saving: [subscription], deleting: [])
        } catch {
            throw RemoteChannelError.unreachable
        }
    }

    // MARK: - Private

    private func poll(device: String, into continuation: AsyncStream<RemoteMessage>.Continuation) async {
        var seen: Set<String> = []
        var logged = false
        // The first read is the backlog; what a later read finds was stored since: live.
        var backlog = true
        while !Task.isCancelled {
            do {
                let found = try await query(NSPredicate(format: "%K == %@", Field.to, device))
                for var m in found where seen.insert(m.id).inserted {
                    m.isLive = !backlog
                    continuation.yield(m)
                }
                backlog = false
                // Forget what is gone: the set stays the size of the zone.
                seen.formIntersection(found.map(\.id))
            } catch {
                // Once per stream: a dead network would otherwise log every 2 s.
                if !logged { Self.log.error("remote messages not read") }
                logged = true
            }
            do { try await Task.sleep(for: pollInterval) } catch { break }
        }
        continuation.finish()
    }

    private func query(_ predicate: NSPredicate) async throws -> [RemoteMessage] {
        try await ensureZone()
        var out: [RemoteMessage] = []
        var (results, cursor) = try await database.records(
            matching: CKQuery(recordType: Self.recordType, predicate: predicate), inZoneWith: zoneID)
        while true {
            for (_, result) in results {
                if case .success(let record) = result, let m = Self.message(record) { out.append(m) }
            }
            guard let next = cursor else { return out }
            (results, cursor) = try await database.records(continuingMatchFrom: next)
        }
    }

    private func ensureZone() async throws {
        guard !zoneReady else { return }
        _ = try await database.modifyRecordZones(saving: [CKRecordZone(zoneID: zoneID)], deleting: [])
        zoneReady = true
    }

    private func recordID(_ name: String) -> CKRecord.ID {
        CKRecord.ID(recordName: name, zoneID: zoneID)
    }

    private static func message(_ record: CKRecord) -> RemoteMessage? {
        guard let to = record[Field.to] as? String, let blob = record[Field.blob] as? Data,
              let expiresAt = record[Field.expiresAt] as? Date
        else { return nil }
        return RemoteMessage(
            id: record.recordID.recordName, to: to, blob: blob, expiresAt: expiresAt, sentAt: record.creationDate)
    }
}
#endif
