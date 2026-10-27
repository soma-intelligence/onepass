import CloudKit
import Foundation

/// Pure conversions between `RemoteRecord` and CloudKit types. Always compiled, testable without an
/// iCloud account (nothing here touches `CKContainer`).
public enum CloudKitMapping {
    public static let zoneName = "OnePass"
    public static let recordType = "OPRecord"
    public static let subscriptionID = "onepass.database"

    /// A CloudKit record that does not describe a valid `RemoteRecord`.
    public enum MappingError: Error, Equatable {
        case invalidName
        case missingField(String)
        case kindMismatch
        /// A deletion has no CloudKit record to build.
        case deletion
    }

    // MARK: - Records

    /// The CloudKit record to save for `remote`. Starts from the stored system fields when `serverMeta`
    /// is set (conditional save), from a new record otherwise (the record must not exist).
    public static func record(from remote: RemoteRecord, zoneID: CKRecordZone.ID) throws -> CKRecord {
        guard let data = remote.data else { throw MappingError.deletion }
        let recordID = CKRecord.ID(recordName: remote.name.string, zoneID: zoneID)
        let record: CKRecord
        if let meta = remote.serverMeta, let known = self.record(fromSystemFields: meta),
            known.recordID.recordName == recordID.recordName,
            known.recordID.zoneID.zoneName == zoneID.zoneName
        {
            record = known
        } else {
            record = CKRecord(recordType: recordType, recordID: recordID)
        }
        record["kind"] = Int64(remote.name.kind)
        record["version"] = Int64(truncatingIfNeeded: remote.version)
        record.encryptedValues["data"] = data
        return record
    }

    /// The remote record of a present CloudKit record. A record without `data` is invalid, not a
    /// deletion (deletions come from the deleted list, see `deletion(recordID:)`).
    public static func remote(from record: CKRecord) throws -> RemoteRecord {
        guard record.recordType == recordType else { throw MappingError.invalidName }
        guard let name = RecordName(string: record.recordID.recordName) else { throw MappingError.invalidName }
        guard let kind = record["kind"] as? Int64 else { throw MappingError.missingField("kind") }
        guard let version = record["version"] as? Int64, version >= 0 else {
            throw MappingError.missingField("version")
        }
        guard kind == Int64(name.kind) else { throw MappingError.kindMismatch }
        guard let data = record.encryptedValues["data"] as? Data else { throw MappingError.missingField("data") }
        return RemoteRecord(
            name: name, version: UInt64(version), data: data, serverMeta: systemFields(of: record))
    }

    /// A record deleted on the server.
    public static func deletion(recordID: CKRecord.ID) throws -> RemoteRecord {
        guard let name = RecordName(string: recordID.recordName) else { throw MappingError.invalidName }
        return RemoteRecord(name: name, version: 0, data: nil, serverMeta: nil)
    }

    // MARK: - System fields

    public static func systemFields(of record: CKRecord) -> Data {
        let coder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: coder)
        coder.finishEncoding()
        return coder.encodedData
    }

    public static func record(fromSystemFields data: Data) -> CKRecord? {
        guard let coder = try? NSKeyedUnarchiver(forReadingFrom: data) else { return nil }
        coder.requiresSecureCoding = true
        defer { coder.finishDecoding() }
        return CKRecord(coder: coder)
    }

    /// Whether two `serverMeta` values describe the same server version. System field archives compare by
    /// `recordChangeTag` (the archive bytes can differ for the same version); anything else by bytes.
    public static func sameServerVersion(_ lhs: Data, _ rhs: Data) -> Bool {
        if let left = record(fromSystemFields: lhs), let right = record(fromSystemFields: rhs),
            let leftTag = left.recordChangeTag, let rightTag = right.recordChangeTag
        {
            return left.recordID.recordName == right.recordID.recordName && leftTag == rightTag
        }
        return lhs == rhs
    }

    // MARK: - Tokens

    public static func encode(token: CKServerChangeToken) -> Data? {
        try? NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
    }

    /// nil for nil or unreadable data (a full fetch is always safe).
    public static func decodeToken(_ data: Data?) -> CKServerChangeToken? {
        guard let data else { return nil }
        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: CKServerChangeToken.self, from: data)
    }

    /// A fetched page. `moreComing` is never true without a token (a caller would loop forever).
    public static func batch(changes: [RemoteRecord], moreComing: Bool, token: Data?) -> RemoteBatch {
        RemoteBatch(changes: changes, moreComing: moreComing && token != nil, token: token)
    }

    // MARK: - Errors

    /// A zone that is gone from the server.
    public enum ZoneLoss: Equatable, Sendable {
        /// `zoneNotFound`: the zone never existed or was deleted.
        case notFound
        /// `userDeletedZone`: the user deleted the data in iCloud settings.
        case userDeleted
    }

    /// The zone loss in `error`, also when it comes inside a partial failure.
    public static func zoneLoss(in error: Error) -> ZoneLoss? {
        guard let ck = error as? CKError else { return nil }
        switch ck.code {
        case .zoneNotFound: return .notFound
        case .userDeletedZone: return .userDeleted
        case .partialFailure:
            let nested = (ck.partialErrorsByItemID ?? [:]).values.compactMap { zoneLoss(in: $0) }
            return nested.contains(.userDeleted) ? .userDeleted : nested.first
        default: return nil
        }
    }

    /// Whether the zone has to be created again before a retry.
    public static func requiresZoneRecreation(_ error: Error) -> Bool {
        zoneLoss(in: error) != nil
    }

    /// Whether a recreated zone means the server lost data we hold state for (the caller must upload
    /// everything again) rather than a zone that was simply not created yet. `hadState`: a change token
    /// was given, or a sent record carried server metadata.
    public static func resetsStore(_ loss: ZoneLoss, hadState: Bool) -> Bool {
        loss == .userDeleted || hadState
    }

    /// The store error of a CloudKit failure, nil when `error` needs a case by case answer
    /// (`serverRecordChanged`, `unknownItem`, `zoneNotFound`, `changeTokenExpired`, partial failures).
    public static func storeError(for error: Error) -> RemoteStoreError {
        if let store = error as? RemoteStoreError { return store }
        if error is URLError { return .offline }
        guard let ck = error as? CKError else {
            return .other(String(localized: "Erreur iCloud inattendue.", bundle: VaultKitStrings.bundle))
        }
        switch ck.code {
        case .networkUnavailable, .networkFailure:
            return .offline
        case .notAuthenticated, .accountTemporarilyUnavailable:
            return .accountUnavailable
        case .requestRateLimited, .zoneBusy, .serviceUnavailable:
            return .retryable(after: ck.retryAfterSeconds.map { .seconds($0) })
        case .limitExceeded:
            return .other(String(localized: "Lot trop volumineux pour iCloud", bundle: VaultKitStrings.bundle))
        case .quotaExceeded:
            return .other(String(localized: "Espace iCloud insuffisant.", bundle: VaultKitStrings.bundle))
        default:
            return .other(String(localized: "Erreur iCloud (\(ck.code.rawValue)).", bundle: VaultKitStrings.bundle))
        }
    }

    /// The outcome of one record of an atomic batch, or the error to throw for the whole call.
    public static func sendResult(
        name: RecordName, isDeletion: Bool, error: Error
    ) -> Result<SendResult, RemoteStoreError> {
        guard let ck = error as? CKError else { return .failure(storeError(for: error)) }
        switch ck.code {
        case .batchRequestFailed:
            return .success(.failed(name: name))
        case .unknownItem where isDeletion:
            return .success(.saved(name: name, serverMeta: nil))
        case .unknownItem:
            return .success(.conflict(server: RemoteRecord(name: name, version: 0, data: nil, serverMeta: nil)))
        case .serverRecordChanged:
            if let server = ck.userInfo[CKRecordChangedErrorServerRecordKey] as? CKRecord,
                let remote = try? remote(from: server)
            {
                return .success(.conflict(server: remote))
            }
            // No readable server record: never a deletion (only `unknownItem` on a save means that).
            return .success(.failed(name: name))
        default:
            return .failure(storeError(for: error))
        }
    }
}
