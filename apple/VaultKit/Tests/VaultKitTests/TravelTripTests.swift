import CryptoKit
import Foundation
import Testing

@testable import VaultKit

@Suite("Travel trips model")
struct TravelTripTests {
    // What the shipped version writes: none of the new fields.
    static let oldJSON =
        #"{"seen":{"u09":[100,101,102]},"taught":["xn7"],"tripSnoozed":true,"tripNotified":false,"welcomeDismissed":false,"travelActive":false}"#

    @Test func oldFileStillOpens() throws {
        let places = try JSONDecoder().decode(TravelPlaces.self, from: Data(Self.oldJSON.utf8))
        #expect(places.seen["u09"] == [100, 101, 102])
        #expect(places.taught == ["xn7"])
        #expect(places.tripSnoozed)
        #expect(places.trips.isEmpty)
        #expect(places.usualOffsets.isEmpty)
        #expect(places.seenEventIDs.isEmpty)
        #expect(places.lastCalendarScan == nil)
        #expect(places.lastAirportNotice == nil)
        #expect(places.welcomeTripDismissed == nil)
    }

    @Test func roundTripKeepsTrips() throws {
        var places = TravelPlaces()
        let trip = TravelTrip(
            start: Date(timeIntervalSince1970: 1_800_000_000),
            end: Date(timeIntervalSince1970: 1_800_600_000), autoEnter: true)
        places.trips = [trip]
        places.usualOffsets["Europe/Paris|3600"] = [100]
        places.seenEventIDs = ["ev1"]
        places.lastCalendarScan = 12.5
        places.lastAirportNotice = 7
        places.welcomeTripDismissed = trip.id
        places.seen = ["u09": [1, 2]]
        let back = try JSONDecoder().decode(TravelPlaces.self, from: JSONEncoder().encode(places))
        #expect(back == places)
    }

    @Test func tripDefaults() {
        let trip = TravelTrip(start: Date(timeIntervalSince1970: 0), end: Date(timeIntervalSince1970: 10))
        #expect(trip.source == .manual)
        #expect(!trip.autoEnter)
        #expect(trip.calendarEventID == nil)
        #expect(!trip.autoTried)
    }

    @Test func storeReopensOldFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let keychain = InMemoryKeychain()
        let keyData = Data((0..<32).map { UInt8($0) })
        try keychain.write(TravelPlacesStore.keyName, keyData)
        let sealed = try AES.GCM.seal(Data(Self.oldJSON.utf8), using: SymmetricKey(data: keyData))
        let url = dir.appendingPathComponent("places.bin")
        try #require(sealed.combined).write(to: url)
        let store = TravelPlacesStore(url: url, keychain: keychain)
        let places = store.load()
        #expect(places.seen["u09"] == [100, 101, 102])
        #expect(places.taught == ["xn7"])
        #expect(places.trips.isEmpty)
    }

    @Test func storeTellsMissingFromUnreadable() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("travel-places.bin")
        let keychain = InMemoryKeychain()
        let store = TravelPlacesStore(url: url, keychain: keychain)
        #expect(store.open() == .missing)
        var places = TravelPlaces()
        places.trips = [
            TravelTrip(
                start: Date(timeIntervalSince1970: 1_800_000_000), end: Date(timeIntervalSince1970: 1_800_600_000))
        ]
        try store.save(places)
        #expect(store.open() == .opened(places))
        // The keychain refuses while the device is locked: the file is there, not readable now.
        let locked = TravelPlacesStore(url: url, keychain: LockedKeychain())
        #expect(locked.open() == .unreadable)
        // A file that does not decrypt is not missing either.
        let other = InMemoryKeychain()
        try other.write(TravelPlacesStore.keyName, Data(repeating: 7, count: 32))
        #expect(TravelPlacesStore(url: url, keychain: other).open() == .unreadable)
        // A file that opens but does not decode is forgotten.
        let keyData = try #require(try keychain.read(TravelPlacesStore.keyName))
        let sealed = try AES.GCM.seal(Data("not json".utf8), using: SymmetricKey(data: keyData))
        try #require(sealed.combined).write(to: url)
        #expect(store.open() == .missing)
    }
}

/// A keychain as on a locked device: every read is refused.
private struct LockedKeychain: KeychainStore {
    struct Locked: Error {}
    func read(_ key: String) throws -> Data? { throw Locked() }
    func write(_ key: String, _ data: Data) throws { throw Locked() }
    func delete(_ key: String) throws { throw Locked() }
    func writeAfterFirstUnlock(_ key: String, _ data: Data) throws { throw Locked() }
}
