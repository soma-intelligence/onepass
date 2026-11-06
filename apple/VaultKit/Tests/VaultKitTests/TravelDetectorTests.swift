import Foundation
import Testing

@testable import VaultKit

/// Travel detection (spec 2026-11-02, section 6): geohash cells computed on the device, usual
/// places learned over days, one suggestion per trip, and the encrypted local file.
@Suite("Travel detection")
struct TravelDetectorTests {
    // Paris, Lyon (about 390 km), Versailles (about 17 km), Tokyo.
    let paris = TravelDetector.cell(latitude: 48.8566, longitude: 2.3522)
    let versailles = TravelDetector.cell(latitude: 48.8049, longitude: 2.1204)
    let lyon = TravelDetector.cell(latitude: 45.7640, longitude: 4.8357)
    let tokyo = TravelDetector.cell(latitude: 35.6762, longitude: 139.6503)

    @Test func geohashKnownVectors() {
        #expect(Geohash.encode(latitude: 57.64911, longitude: 10.40744, precision: 11) == "u4pruydqqvj")
        #expect(paris == "u09")
        #expect(tokyo == "xn7")
        let b = Geohash.bounds("u09")!
        #expect(b.0 < 48.8566 && 48.8566 < b.1 && b.2 < 2.3522 && 2.3522 < b.3)
    }

    @Test func neighbourhoodHasNineCellsAndWrapsLongitude() {
        let around = Geohash.neighbourhood(paris)
        #expect(around.count == 9)
        #expect(around.contains(paris))
        #expect(around.contains(versailles))
        #expect(!around.contains(tokyo))
        // A cell on the antimeridian sees the cells on the other side.
        let east = Geohash.encode(latitude: 0, longitude: 179.9, precision: 3)
        let west = Geohash.encode(latitude: 0, longitude: -179.9, precision: 3)
        #expect(Geohash.neighbourhood(east).contains(west))
        // At a pole, no row beyond it.
        #expect(Geohash.neighbourhood(Geohash.encode(latitude: 89.9, longitude: 0, precision: 3)).count == 6)
    }

    private func home(days: Int = 3) -> TravelPlaces {
        var places = TravelPlaces()
        for day in 0..<days { TravelDetector.observe(&places, cell: paris, day: 100 + day) }
        return places
    }

    @Test func learnsBeforeSuggestingAnything() {
        var places = TravelPlaces()
        #expect(TravelDetector.check(&places, cell: paris, day: 1, travelling: false) == .none)
        #expect(TravelDetector.check(&places, cell: paris, day: 2, travelling: false) == .none)
        // Two days observed only: abroad is still "learning".
        #expect(TravelDetector.verdict(places, cell: tokyo) == .learning)
        _ = TravelDetector.check(&places, cell: paris, day: 3, travelling: false)
        #expect(TravelDetector.verdict(places, cell: tokyo) == .away(cell: tokyo))
        #expect(TravelDetector.verdict(places, cell: versailles) == .home)
    }

    @Test func oneSuggestionAndOneNotificationPerTrip() {
        var places = home()
        #expect(TravelDetector.check(&places, cell: tokyo, day: 110, travelling: false)
            == .suggest(cell: tokyo, notify: true))
        // The card stays until answered, the notification does not repeat.
        #expect(TravelDetector.check(&places, cell: tokyo, day: 110, travelling: false)
            == .suggest(cell: tokyo, notify: false))
        #expect(places.pendingCell == tokyo)
        TravelDetector.snooze(&places)
        #expect(places.pendingCell == nil)
        #expect(TravelDetector.check(&places, cell: tokyo, day: 111, travelling: false) == .none)
        // Home ends the trip; the next one asks again.
        #expect(TravelDetector.check(&places, cell: paris, day: 112, travelling: false) == .none)
        #expect(TravelDetector.check(&places, cell: lyon, day: 113, travelling: false)
            == .suggest(cell: lyon, notify: true))
    }

    @Test func noTeachesThePlace() {
        var places = home()
        _ = TravelDetector.check(&places, cell: lyon, day: 110, travelling: false)
        TravelDetector.teach(&places, cell: lyon)
        #expect(places.pendingCell == nil)
        #expect(TravelDetector.check(&places, cell: lyon, day: 110, travelling: false) == .none)
        #expect(TravelDetector.verdict(places, cell: lyon) == .home)
    }

    @Test func travellingSuggestsNothingAbroadAndWelcomesBackHome() {
        var places = home()
        #expect(TravelDetector.check(&places, cell: tokyo, day: 110, travelling: true) == .none)
        // A trip in Travel Mode teaches nothing.
        for day in 110..<120 { _ = TravelDetector.check(&places, cell: tokyo, day: day, travelling: true) }
        #expect(places.seen[tokyo] == nil)
        #expect(TravelDetector.check(&places, cell: paris, day: 121, travelling: true) == .welcomeBack)
        places.welcomeDismissed = true
        #expect(TravelDetector.check(&places, cell: paris, day: 121, travelling: true) == .none)
    }

    @Test func oldDaysAndCellsAreTrimmed() {
        var places = TravelPlaces()
        TravelDetector.observe(&places, cell: lyon, day: 1)
        TravelDetector.observe(&places, cell: paris, day: 1 + TravelDetector.windowDays)
        #expect(places.seen[lyon] == nil)
        for i in 0..<(TravelDetector.maxCells + 5) {
            TravelDetector.observe(&places, cell: "c\(i)", day: 200 + i / 2)
        }
        #expect(places.seen.count == TravelDetector.maxCells)
        #expect(places.seen["c0"] == nil)
    }

    @Test func storeRoundTripsSealedAndWipes() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keychain = InMemoryKeychain()
        let store = TravelPlacesStore(url: dir.appendingPathComponent("places.bin"), keychain: keychain)
        #expect(store.load() == TravelPlaces())
        let places = home()
        try store.save(places)
        #expect(store.load() == places)
        // Sealed: the cell names are not in the file.
        let bytes = try Data(contentsOf: store.url)
        #expect(bytes.range(of: Data(paris.utf8)) == nil)
        // Without its key the file is unreadable: learning starts again.
        try keychain.delete(TravelPlacesStore.keyName)
        #expect(store.load() == TravelPlaces())
        try store.save(places)
        try store.wipe()
        #expect(!FileManager.default.fileExists(atPath: store.url.path))
        #expect(try keychain.read(TravelPlacesStore.keyName) == nil)
        #expect(store.load() == TravelPlaces())
    }
}
