import CloudKit
import Foundation
import Testing

@testable import VaultKit

@Suite("CloudKit mapping")
struct CloudKitMappingTests {
    /// Messages are compared in French, the source language, whatever the machine's language.
    init() { VaultKitStrings.pinSourceLanguage() }

    static let name = RecordName(kind: 5, id: "00112233445566778899aabbccddeeff")
    static let zone = CKRecordZone.ID(zoneName: CloudKitMapping.zoneName, ownerName: CKCurrentUserDefaultName)

    @Test func mappingRoundtripsDataAndVersion() throws {
        let remote = RemoteRecord(name: Self.name, version: 42, data: Data([1, 2, 3, 0xFF]), serverMeta: nil)
        let record = try CloudKitMapping.record(from: remote, zoneID: Self.zone)
        #expect(record.recordType == "OPRecord")
        #expect(record.recordID.recordName == Self.name.string)
        #expect(record.recordID.zoneID == Self.zone)
        #expect(record["kind"] as? Int64 == 5)
        #expect(record["version"] as? Int64 == 42)
        let back = try CloudKitMapping.remote(from: record)
        #expect(back.name == Self.name && back.version == 42 && back.data == remote.data)
        #expect(back.serverMeta != nil)
    }

    @Test func systemFieldsRoundtrip() throws {
        let id = CKRecord.ID(recordName: Self.name.string, zoneID: Self.zone)
        let record = CKRecord(recordType: CloudKitMapping.recordType, recordID: id)
        let decoded = try #require(CloudKitMapping.record(fromSystemFields: CloudKitMapping.systemFields(of: record)))
        #expect(decoded.recordID == id)
        #expect(decoded.recordType == CloudKitMapping.recordType)
        #expect(CloudKitMapping.record(fromSystemFields: Data([1, 2, 3])) == nil)
    }

    @Test func saveStartsFromServerMeta() throws {
        let id = CKRecord.ID(recordName: Self.name.string, zoneID: Self.zone)
        let meta = CloudKitMapping.systemFields(of: CKRecord(recordType: CloudKitMapping.recordType, recordID: id))
        let remote = RemoteRecord(name: Self.name, version: 1, data: Data([9]), serverMeta: meta)
        let record = try CloudKitMapping.record(from: remote, zoneID: Self.zone)
        #expect(record.recordID == id)
        #expect(record.encryptedValues["data"] as? Data == Data([9]))
    }

    @Test func deletionHasNoData() throws {
        let id = CKRecord.ID(recordName: Self.name.string, zoneID: Self.zone)
        let deleted = try CloudKitMapping.deletion(recordID: id)
        #expect(deleted.data == nil && deleted.name == Self.name && deleted.serverMeta == nil)
        let remote = RemoteRecord(name: Self.name, version: 3, data: nil, serverMeta: nil)
        #expect(throws: CloudKitMapping.MappingError.deletion) {
            try CloudKitMapping.record(from: remote, zoneID: Self.zone)
        }
        #expect(throws: CloudKitMapping.MappingError.invalidName) {
            try CloudKitMapping.deletion(recordID: CKRecord.ID(recordName: "zone", zoneID: Self.zone))
        }
    }

    @Test func presentRecordWithoutDataIsInvalid() {
        let record = CKRecord(
            recordType: CloudKitMapping.recordType,
            recordID: CKRecord.ID(recordName: Self.name.string, zoneID: Self.zone))
        record["kind"] = Int64(5)
        record["version"] = Int64(1)
        #expect(throws: CloudKitMapping.MappingError.missingField("data")) {
            try CloudKitMapping.remote(from: record)
        }
        record.encryptedValues["data"] = Data([1])
        record["kind"] = Int64(4)
        #expect(throws: CloudKitMapping.MappingError.kindMismatch) {
            try CloudKitMapping.remote(from: record)
        }
    }

    @Test func tokenHelpers() {
        #expect(CloudKitMapping.decodeToken(nil) == nil)
        #expect(CloudKitMapping.decodeToken(Data([1, 2, 3])) == nil)
        let looping = CloudKitMapping.batch(changes: [], moreComing: true, token: nil)
        #expect(!looping.moreComing)
        let paged = CloudKitMapping.batch(changes: [], moreComing: true, token: Data([1]))
        #expect(paged.moreComing)
    }

    @Test func errorsMapToStoreErrors() {
        #expect(CloudKitMapping.storeError(for: CKError(.networkUnavailable)) == .offline)
        #expect(CloudKitMapping.storeError(for: CKError(.networkFailure)) == .offline)
        #expect(CloudKitMapping.storeError(for: URLError(.notConnectedToInternet)) == .offline)
        #expect(CloudKitMapping.storeError(for: CKError(.notAuthenticated)) == .accountUnavailable)
        #expect(CloudKitMapping.storeError(for: CKError(.accountTemporarilyUnavailable)) == .accountUnavailable)
        #expect(CloudKitMapping.storeError(for: CKError(.zoneBusy)) == .retryable(after: nil))
        let limited = CKError(.requestRateLimited, userInfo: [CKErrorRetryAfterKey: 7.0])
        #expect(CloudKitMapping.storeError(for: limited) == .retryable(after: .seconds(7)))
        #expect(CloudKitMapping.storeError(for: CKError(.serviceUnavailable)) == .retryable(after: nil))
        #expect(CloudKitMapping.storeError(for: CKError(.limitExceeded)) == .other("Lot trop volumineux pour iCloud"))
    }

    @Test func perRecordSendResults() throws {
        let name = Self.name
        #expect(try CloudKitMapping.sendResult(name: name, isDeletion: false, error: CKError(.batchRequestFailed)).get()
            == .failed(name: name))
        #expect(try CloudKitMapping.sendResult(name: name, isDeletion: true, error: CKError(.unknownItem)).get()
            == .saved(name: name, serverMeta: nil))
        #expect(try CloudKitMapping.sendResult(name: name, isDeletion: false, error: CKError(.unknownItem)).get()
            == .conflict(server: RemoteRecord(name: name, version: 0, data: nil, serverMeta: nil)))

        // No readable server record: the save failed, it is not a deletion.
        let unreadable = try CloudKitMapping.sendResult(
            name: name, isDeletion: false, error: CKError(.serverRecordChanged)).get()
        #expect(unreadable == .failed(name: name))

        // Server record present.
        let server = try CloudKitMapping.record(
            from: RemoteRecord(name: name, version: 8, data: Data([4]), serverMeta: nil), zoneID: Self.zone)
        let changed = CKError(.serverRecordChanged, userInfo: [CKRecordChangedErrorServerRecordKey: server])
        guard case .conflict(let remote) = try CloudKitMapping.sendResult(
            name: name, isDeletion: false, error: changed).get()
        else { Issue.record("expected a conflict"); return }
        #expect(remote.version == 8 && remote.data == Data([4]) && remote.serverMeta != nil)

        // Anything else aborts the call.
        #expect(throws: RemoteStoreError.offline) {
            try CloudKitMapping.sendResult(name: name, isDeletion: false, error: CKError(.networkUnavailable)).get()
        }
    }

    @Test func zoneLossIsDetectedAlsoInsidePartialFailures() {
        #expect(CloudKitMapping.zoneLoss(in: CKError(.zoneNotFound)) == .notFound)
        #expect(CloudKitMapping.zoneLoss(in: CKError(.userDeletedZone)) == .userDeleted)
        #expect(CloudKitMapping.zoneLoss(in: CKError(.networkFailure)) == nil)
        #expect(CloudKitMapping.zoneLoss(in: URLError(.timedOut)) == nil)
        let id = CKRecord.ID(recordName: Self.name.string, zoneID: Self.zone)
        let other = CKRecord.ID(recordName: "5.ffffffffffffffffffffffffffffffff", zoneID: Self.zone)
        let partial = CKError(
            .partialFailure,
            userInfo: [CKPartialErrorsByItemIDKey: [id: CKError(.batchRequestFailed), other: CKError(.zoneNotFound)]])
        #expect(CloudKitMapping.zoneLoss(in: partial) == .notFound)
        #expect(CloudKitMapping.requiresZoneRecreation(partial))
        #expect(!CloudKitMapping.requiresZoneRecreation(CKError(.serverRecordChanged)))
    }

    @Test func resetOnlyWhenStateWasLost() {
        #expect(CloudKitMapping.resetsStore(.userDeleted, hadState: false))
        #expect(CloudKitMapping.resetsStore(.notFound, hadState: true))
        #expect(!CloudKitMapping.resetsStore(.notFound, hadState: false))
    }

    @Test func sameServerVersionComparesChangeTags() {
        let id = CKRecord.ID(recordName: Self.name.string, zoneID: Self.zone)
        let record = CKRecord(recordType: CloudKitMapping.recordType, recordID: id)
        let meta = CloudKitMapping.systemFields(of: record)
        #expect(CloudKitMapping.sameServerVersion(meta, meta))
        // Non CloudKit metadata (InMemoryRemote tags) compares by bytes.
        #expect(CloudKitMapping.sameServerVersion(Data([1, 0, 0, 0, 0, 0, 0, 0]), Data([1, 0, 0, 0, 0, 0, 0, 0])))
        #expect(!CloudKitMapping.sameServerVersion(Data([1]), Data([2])))
    }
}
