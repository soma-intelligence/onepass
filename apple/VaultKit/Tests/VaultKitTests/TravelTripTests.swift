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
}
