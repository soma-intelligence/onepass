import XCTest

/// iPhone and iPad captures for the visual review, run by `scripts/screenshots.sh` only: skipped
/// unless `ONEPASS_SCREENSHOT_DIR` is set (xcodebuild passes `TEST_RUNNER_ONEPASS_SCREENSHOT_DIR`).
/// Demonstration data only (Debug `-OnePassDemoData`, fictional values), the onboarding on an
/// emptied store. `ONEPASS_SCREENSHOT_DEVICE` names the files (`iphone`, `ipad`),
/// `ONEPASS_SCREENSHOT_LANDSCAPE=1` turns the device first (the simulator has no rotate command).
@MainActor
final class ScreenshotUITests: XCTestCase {
    private struct Screen {
        let name: String
        let arguments: [String]
        /// Shown once the screen is ready.
        let ready: String
        /// The iPhone tabs (Accueil, Éléments, Watchtower) exist on iPhone only.
        var phoneOnly = false
    }

    /// The list waits for its first row by title (a lazy list only exposes the rows on screen).
    private static let screens: [Screen] = [
        Screen(name: "welcome", arguments: isolated + ["-OnePassUITestReset", "YES"], ready: "onboarding.create"),
        Screen(name: "home", arguments: demo, ready: "home.profile", phoneOnly: true),
        Screen(name: "items", arguments: demo + ["-OnePassDemoTab", "items"], ready: "items.vaults.new", phoneOnly: true),
        Screen(
            name: "watchtower", arguments: demo + ["-OnePassDemoTab", "watchtower"], ready: "page.watchtower",
            phoneOnly: true),
        Screen(name: "locked", arguments: demo + ["-OnePassDemoLocked", "YES"], ready: "lock.password"),
        Screen(name: "list", arguments: demo + ["-OnePassDemoTab", "search"], ready: "list.row.API Cartes Atlas"),
        Screen(name: "detail", arguments: demo + ["-OnePassDemoItem", "Forge Atlas"], ready: "item.title"),
        Screen(
            name: "edit", arguments: demo + ["-OnePassDemoItem", "Forge Atlas", "-OnePassDebugEdit", "YES"],
            ready: "editor.save"),
        // iPhone: Réglages is a tab; iPad and Mac: the sheet or window. Both list "Général".
        Screen(name: "settings", arguments: demo + ["-OnePassDemoSettings", "YES"], ready: "settings.general"),
    ]

    private static let demo = ["-OnePassDemoData", "YES"]
    /// Debug: the app's own test store, defaults suite and keychain service (never the real ones).
    private static let isolated = ["-OnePassTestIsolation", "YES"]

    override func setUp() async throws {
        continueAfterFailure = false
    }

    func testCaptureScreens() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let folder = environment["ONEPASS_SCREENSHOT_DIR"], !folder.isEmpty else {
            throw XCTSkip("captures only: run apple/scripts/screenshots.sh")
        }
        let device = environment["ONEPASS_SCREENSHOT_DEVICE"] ?? "iphone"
        let directory = URL(fileURLWithPath: folder, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let landscape = environment["ONEPASS_SCREENSHOT_LANDSCAPE"] == "1"
        XCUIDevice.shared.orientation = landscape ? .landscapeLeft : .portrait
        let orientation = landscape ? "-landscape" : ""
        defer {
            XCUIDevice.shared.orientation = .portrait
            XCUIDevice.shared.appearance = .light
            // Empties the isolated test store, defaults suite and keychain service.
            let cleanup = XCUIApplication()
            cleanup.launchArguments += Self.isolated + ["-OnePassUITestReset", "YES"]
            cleanup.launch()
            cleanup.terminate()
        }

        for (suffix, appearance) in [("light", XCUIDevice.Appearance.light), ("dark", .dark)] {
            XCUIDevice.shared.appearance = appearance
            for screen in Self.screens where device == "iphone" || !screen.phoneOnly {
                let app = XCUIApplication()
                app.launchArguments += screen.arguments
                app.launch()
                // The demo account is created with the real Argon2id cost.
                let ready = app.descendants(matching: .any)[screen.ready].firstMatch
                XCTAssertTrue(ready.waitForExistence(timeout: 90), "\(screen.name) not shown")
                // Let transitions and the keyboard settle.
                Thread.sleep(forTimeInterval: 1.5)
                let png = XCUIScreen.main.screenshot().pngRepresentation
                let name = "\(device)\(orientation)-\(screen.name)-\(suffix).png"
                try png.write(to: directory.appendingPathComponent(name))
                app.terminate()
            }
        }
    }
}

/// Captures of the iPhone lists for the 2026-11-02 review (header fade, swipe actions, the "+" sheet,
/// search, Watchtower, À proximité): skipped unless `ONEPASS_FEEDBACK_DIR` is set (xcodebuild passes
/// `TEST_RUNNER_ONEPASS_FEEDBACK_DIR`). Demonstration data only, dark appearance.
@MainActor
final class ListsFeedbackCaptureUITests: XCTestCase {
    private var directory: URL!

    override func setUp() async throws {
        continueAfterFailure = true
    }

    private func shot(_ name: String) {
        let png = XCUIScreen.main.screenshot().pngRepresentation
        try? png.write(to: directory.appendingPathComponent("\(name).png"))
    }

    private func launch(_ arguments: [String], ready: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += ["-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO"] + arguments
        app.launch()
        let element = app.descendants(matching: .any)[ready].firstMatch
        XCTAssertTrue(element.waitForExistence(timeout: 90), "\(ready) not shown")
        Thread.sleep(forTimeInterval: 1.2)
        return app
    }

    /// Drags the content up by `points`, slowly, and leaves it there.
    private func scroll(_ app: XCUIApplication, by points: CGFloat, from y: CGFloat = 0.7) {
        let start = app.windows.firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: y))
        let end = start.withOffset(CGVector(dx: 0, dy: -points))
        start.press(forDuration: 0.05, thenDragTo: end, withVelocity: .slow, thenHoldForDuration: 0.3)
        Thread.sleep(forTimeInterval: 0.8)
    }

    func testCaptureListsFeedback() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let folder = environment["ONEPASS_FEEDBACK_DIR"], !folder.isEmpty else {
            throw XCTSkip("captures only")
        }
        directory = URL(fileURLWithPath: folder, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        XCUIDevice.shared.appearance = .dark
        defer { XCUIDevice.shared.appearance = .light }

        // All items: the bar at rest, then scrolled (header edge), then a row swiped open.
        var app = launch(["-OnePassDemoTab", "items", "-OnePassDemoList", "all"], ready: "list.row.API Cartes Atlas")
        shot("01-all-items-rest")
        scroll(app, by: 260)
        shot("02-all-items-scrolled")
        app.terminate()
        app = launch(["-OnePassDemoTab", "items", "-OnePassDemoList", "all"], ready: "list.row.API Cartes Atlas")
        let row = app.descendants(matching: .any)["list.row.API Cartes Atlas"].firstMatch
        let right = row.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5))
        right.press(forDuration: 0.05, thenDragTo: right.withOffset(CGVector(dx: -170, dy: 0)), withVelocity: .slow,
            thenHoldForDuration: 0.2)
        Thread.sleep(forTimeInterval: 0.8)
        shot("03-all-items-swipe")
        app.terminate()

        // The "+" sheet scrolled under its title and search field.
        app = launch(["-OnePassDemoNewItem", "YES"], ready: "newItem.search")
        shot("04-new-item-rest")
        scroll(app, by: 220, from: 0.75)
        shot("05-new-item-scrolled")
        app.terminate()

        // Search: before typing, results, nothing found.
        app = launch(["-OnePassDemoTab", "search"], ready: "tab.search")
        shot("06-search-start")
        app.terminate()
        app = launch(["-OnePassDemoQuery", "atlas"], ready: "list.row.API Cartes Atlas")
        shot("07-search-results")
        app.terminate()
        app = launch(["-OnePassDemoQuery", "zzqx"], ready: "search.empty")
        shot("08-search-nothing")
        app.terminate()

        // Watchtower: a check's items, scrolled (the header of a pushed list), then a new scan.
        app = launch(["-OnePassDemoTab", "watchtower"], ready: "page.watchtower")
        let card = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'watchtower.show.'"))
            .firstMatch
        if card.waitForExistence(timeout: 20) {
            card.tap()
            Thread.sleep(forTimeInterval: 1)
            shot("09-watchtower-list-rest")
            scroll(app, by: 200)
            shot("10-watchtower-list-scrolled")
            app.navigationBars.buttons.firstMatch.tap()
            Thread.sleep(forTimeInterval: 0.8)
        }
        let top = app.windows.firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3))
        top.press(forDuration: 0.05, thenDragTo: top.withOffset(CGVector(dx: 0, dy: 300)), withVelocity: .fast,
            thenHoldForDuration: 0.1)
        Thread.sleep(forTimeInterval: 0.25)
        shot("11-watchtower-scan")
        app.terminate()

        // À proximité from Éléments (the simulator's location is set by the caller).
        app = launch(["-OnePassDemoTab", "items"], ready: "items.vaults.new")
        let nearby = app.descendants(matching: .any)["items.nearby"].firstMatch
        if nearby.waitForExistence(timeout: 10) {
            nearby.tap()
            Thread.sleep(forTimeInterval: 3)
            shot("12-nearby")
        }
        app.terminate()
    }
}
