import XCTest

/// Planned trips (Réglages > Travel Mode > Voyages) and the "Ton voyage commence" card, on the demo
/// account. `-travel-seed-trip <hours>,<YES|NO>` (Debug only) plants a week long trip leaving in
/// `hours`; the card shows from 3 hours before departure. The automatic entry is not driven here:
/// the demo has no iCloud upstream, so `enterTravel` cannot succeed (covered by unit tests).
@MainActor
final class TravelTripUITests: XCTestCase {
    private static let seedTimeout: TimeInterval = 900
    private static let uiTimeout: TimeInterval = 15
    /// A trip row: `settings.travel.trip.<uuid>`.
    private static let tripRow = NSPredicate(format: "identifier BEGINSWITH 'settings.travel.trip.'")
    private static let addTripButton = NSPredicate(format: "identifier == 'settings.travel.addTrip'")

    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = false
    }

    private func launch(seedTrip: String? = nil) {
        app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
            "-AppleLanguages", "(fr)", "-AppleLocale", "fr_FR",
        ]
        if let seedTrip { app.launchArguments += ["-travel-seed-trip", seedTrip] }
        app.launch()
        XCTAssertTrue(element("account.menu").waitForExistence(timeout: Self.seedTimeout), "demo vault not shown")
    }

    private func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    private func tripRows() -> XCUIElementQuery {
        app.buttons.matching(Self.tripRow)
    }

    /// Account panel > Réglages > Travel Mode.
    private func openTravelSettings() {
        element("account.menu").tap()
        let settings = element("account.settings")
        XCTAssertTrue(settings.waitForExistence(timeout: Self.uiTimeout), "account panel without Réglages")
        settings.tap()
        XCTAssertTrue(element("settings.done").waitForExistence(timeout: 90), "Réglages never opened")
        let row = element("settings.travel")
        var swipes = 0
        while !(row.exists && row.isHittable), swipes < 4 {
            app.swipeUp()
            swipes += 1
        }
        XCTAssertTrue(row.waitForExistence(timeout: Self.uiTimeout), "no Travel Mode row")
        row.tap()
    }

    private var addTrip: XCUIElement { app.buttons.matching(Self.addTripButton).firstMatch }

    private func scrollToTrips() {
        let add = addTrip
        var swipes = 0
        while !(add.exists && add.isHittable), swipes < 6 {
            app.swipeUp()
            swipes += 1
        }
        XCTAssertTrue(add.exists, "Travel Mode page without Ajouter un voyage")
    }

    func testAddTripShowsInList() throws {
        launch()
        openTravelSettings()
        scrollToTrips()
        let before = tripRows().count
        addTrip.tap()
        let save = element("trip.save")
        XCTAssertTrue(save.waitForExistence(timeout: Self.uiTimeout), "the trip editor did not open")
        save.tap()
        XCTAssertTrue(save.waitForNonExistence(timeout: 120), "editor still open after Enregistrer")
        scrollToTrips()
        XCTAssertTrue(addTrip.waitForExistence(timeout: Self.uiTimeout))
        let after = NSPredicate { _, _ in self.tripRows().count > before }
        let grew = XCTNSPredicateExpectation(predicate: after, object: nil)
        XCTAssertEqual(XCTWaiter().wait(for: [grew], timeout: Self.uiTimeout), .completed,
                       "the new trip is missing from the list (\(before) rows before)")

        // The trip starts now, so it would show the card in the next test: delete it.
        tripRows().firstMatch.swipeLeft()
        let delete = app.buttons["Supprimer"].firstMatch
        XCTAssertTrue(delete.waitForExistence(timeout: Self.uiTimeout), "no Supprimer on the trip row")
        delete.tap()
        let gone = NSPredicate { _, _ in self.tripRows().count == before }
        let removed = XCTNSPredicateExpectation(predicate: gone, object: nil)
        XCTAssertEqual(XCTWaiter().wait(for: [removed], timeout: Self.uiTimeout), .completed, "trip not deleted")
    }

    func testTripStartingCardOnLaunch() throws {
        launch(seedTrip: "2,NO")
        let card = element("travel.suggest")
        XCTAssertTrue(card.waitForExistence(timeout: Self.uiTimeout), "no trip card on Accueil")
        XCTAssertTrue(app.staticTexts["Ton voyage commence"].waitForExistence(timeout: 5), "wrong card title")
        XCTAssertFalse(element("travel.suggest.error").exists, "an error line without an automatic trip")

        // The trip is listed in Réglages while it is planned.
        openTravelSettings()
        scrollToTrips()
        XCTAssertTrue(tripRows().firstMatch.waitForExistence(timeout: Self.uiTimeout), "seeded trip not listed")
        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(element("settings.done").waitForExistence(timeout: Self.uiTimeout))
        element("settings.done").tap()
        XCTAssertTrue(element("settings.done").waitForNonExistence(timeout: Self.uiTimeout))

        let no = element("travel.suggest.no")
        XCTAssertTrue(no.waitForExistence(timeout: Self.uiTimeout))
        no.tap()
        XCTAssertTrue(card.waitForNonExistence(timeout: Self.uiTimeout), "card still there after Non")

        openTravelSettings()
        scrollToTrips()
        XCTAssertTrue(addTrip.exists)
        XCTAssertTrue(tripRows().firstMatch.waitForNonExistence(timeout: 5), "trip still listed after Non")
    }

    func testNoCardOutsideWindow() throws {
        launch(seedTrip: "5,NO")
        XCTAssertFalse(element("travel.suggest").waitForExistence(timeout: 5), "card shown 5 h before departure")
    }
}
